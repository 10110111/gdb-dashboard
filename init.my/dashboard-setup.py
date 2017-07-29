class x86regs(Dashboard.Module):
    "x86 general-purpose registers view"

    def __init__(self):
        self.table={}

    def label(self):
        return 'GPRs'

    @staticmethod
    def formatRegName(name):
        return ansi(name,R.style_low)
    @staticmethod
    def formatRegValue(value,changed):
        return ansi(value,R.style_selected_1 if changed else '')
    @classmethod
    def formatReg(self,name,value,changed):
        return self.formatRegName(name)+' '+x86regs.formatRegValue(value,changed)
    @staticmethod
    def getSymbolicPos(addrStr):
        addrWithSymPos=run("x/i $pc").split('\t')[0]
        if not addrWithSymPos.startswith("=> ") or not addrWithSymPos.endswith(":"):
            raise Exception("bad symbolic pos: \""+addrWithSymPos+"\"")
        else:
            return re.sub("=> [^ ]+ ?(.*):","\\1",addrWithSymPos)

    @staticmethod
    def x87RoundingModeString(mode):
        return { 0: "NEAR",
                 1: "DOWN",
                 2: "  UP",
                 3: "ZERO" }[mode]
    @staticmethod
    def x87PrecisionString(mode):
        return {0:"24",1:"??",2:"53",3:"64"}[mode]

    @staticmethod
    def fpuStackFaultDetail(statusWord):
        invalidOperationException=statusWord & 0x01
        C1=statusWord&(1<<9)
        stackFault=statusWord&0x40
        if invalidOperationException and stackFault:
            return "Stack overflow" if C1 else "Stack underflow"
        return ""
    @staticmethod
    def fpuComparExplain(statusWord):
        C0=int((statusWord&(1<<8))!=0)
        C2=int((statusWord&(1<<10))!=0)
        C3=int((statusWord&(1<<14))!=0)
        if C3==0 and C2==0 and C0==0: return "GT"
        if C3==0 and C2==0 and C0==1: return "LT"
        if C3==1 and C2==0 and C0==0: return "EQ"
        if C3==1 and C2==1 and C0==1: return "Unordered"
        return ""
    @staticmethod
    def fpuExplainPE(statusWord):
        if statusWord&(1<<5):
            C1=statusWord&(1<<9)
            return "Rounded UP" if C1 else "Rounded DOWN"
        return ""
    @classmethod
    def fsrComment(self,statusWord):
        stackFaultDetail=self.fpuStackFaultDetail(statusWord)
        comparisonResult=self.fpuComparExplain(statusWord)
        comparComment="" if not comparisonResult else '('+comparisonResult+')'
        peExplanation=self.fpuExplainPE(statusWord)

        comment=comparComment
        if len(comment) and len(stackFaultDetail): comment+=", "
        comment+=stackFaultDetail
        if len(comment) and len(peExplanation): comment+=", "
        comment+=peExplanation
        return comment.rstrip()
    @staticmethod
    def fpuTagString(tag):
        return { 0: "valid  ",
                 1: "zero   ",
                 2: "special",
                 3: "empty  " }[tag]

    @staticmethod
    def getFloatType(exponent,mantissa):
        mantissaLength=64
        expLength=80-mantissaLength-1
        integerBitOnly=1<<(mantissaLength-1)
        QNaN_mask=3<<(mantissaLength-2)
        expMax=(1<<expLength)-1
	integerBitSet=bool(mantissa & integerBitOnly)

        if exponent==expMax:
            if mantissa==integerBitOnly:
                return ("INF","infinity")   # |S|11..11|1.000..0|
            elif((mantissa & QNaN_mask) == QNaN_mask):
                return ("QNaN","quiet NaN")  # |S|11..11|1.1XX..X|
            elif (mantissa & QNaN_mask) == integerBitOnly:
                return ("SNaN","signaling NaN")  # |S|11..11|1.0XX..X|
            else:
                return ("BAD", "unsupported") # all exp bits set, but integer bit reset - pseudo-NaN/Inf
        elif exponent==0:
            if mantissa==0:
                return ("Zero","zero") # |S|00..00|00..00|
            else:
                if not integerBitSet:
                    return ("Denormal","denormal")  # |S|00..00|0.XXXX..X|
                else:
                    return ("BAD","pseudo-denormal") # |S|00..00|1.XXXX..X|
        else:
            if integerBitSet:
                return ("Normal","normal")
            else:
                return ("BAD","unsupported"); # integer bit reset but exp is as if normal - unnormal

    @classmethod
    def formatBadFloat80(self,raw):
        # TODO: print pseudo-denormals as numbers (see EDB)
        sign=bool(int(raw[0],16)&8)
        exponent=int(raw[0:4],16)&0x7fff
        mantissa=int(raw[4:20],16)
        type=self.getFloatType(exponent,mantissa)
        signStr='-' if sign else '+'
        result=signStr+type[0]+' '+re.sub("(.{4})(.{8})(.{8})","\\1 \\2 \\3",raw)
        if type[0]=="BAD":
            result+="  "+type[1]
        return result

    @staticmethod
    def formatGrayedOutLinuxVT(value):
        # Bold black is good enough as gray in Linux VT
        return "\x1b[1;30m"+value+"\x1b[m"
    @staticmethod
    def formatGrayedOutANSI(value):
        return "\x1b[38;5;7m"+value+"\x1b[0m"
    @classmethod
    def formatGrayedOut(self,value):
        if os.environ["TERM"]=="linux":
            return self.formatGrayedOutLinuxVT(value)
        else:
            return self.formatGrayedOutANSI(value)

    def checkAndUpdateChanged(self,key,value):
        savedValue=self.table.get(key,None)
        self.table[key]=value
        changed=self.table and savedValue!=None and savedValue!=value
        return changed
    def formatAndUpdateReg(self,name,value,prefix=''):
        changed=self.checkAndUpdateChanged(prefix+name,value)
        return self.formatReg(name,value,changed)
    def formatAndUpdateRegValue(self,name,value):
        changed=self.checkAndUpdateChanged(name,value)
        return x86regs.formatRegValue(value,changed)
    def formatAndUpdateFlag(self,name,value):
        changed=self.checkAndUpdateChanged('flag'+name,value)
        return self.formatReg(name[0],value,changed)
    def formatAndUpdateFPUTag(self,index,value):
        changed=self.checkAndUpdateChanged('fpu-tag-%x' % index,value)
        return self.formatRegValue(self.fpuTagString(value),changed)

    def linesGPR(self,termWidth,styleChanged):
        if self.bits==32:
            regNames=["EAX","ECX","EDX","EBX","ESP","EBP","ESI","EDI"]
            regValues=run('printf "%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x",'+
                          '$eax,$ecx,$edx,$ebx,$esp,$ebp,$esi,$edi').split(',')
            origAX=run('printf "%08x",$orig_eax')
            origAXint=gdb.parse_and_eval("$orig_eax")
            if len(regValues)!=8:
                raise Exception("32-bit general-purpose registers unavailable")
        else:
            regNames=["RAX","RCX","RDX","RBX","RSP","RBP","RSI","RDI",
                      "R8 ","R9 ","R10","R11","R12","R13","R14","R15"]
            regValues=run('printf "%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,'+
                          '%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,%016lx,%016lx",'+
                          '$rax,$rcx,$rdx,$rbx,$rsp,$rbp,$rsi,$rdi,'+
                          '$r8,$r9,$r10,$r11,$r12,$r13,$r14,$r15').split(',')
            origAX=run('printf "%016lx",$orig_rax')
            origAXint=gdb.parse_and_eval("$orig_rax")
            if len(regValues)!=16:
                raise Exception("64-bit general-purpose registers unavailable")

        regs=dict(zip(regNames,regValues))
        registers=[]
        for name in regNames:
            value=regs[name]
            registers.append(self.formatAndUpdateReg(name,value))
        if origAXint!=-1:
            registers[0]+=self.formatGrayedOut(" orig: "+origAX)
        return registers

    def linesPC(self,termWidth,styleChanged):
        if self.bits==32:
            name="EIP"
            value=run(r'printf "%08x", $pc')
        else:
            name="RIP"
            value=run(r'printf "%016lx", $pc')
        comment=self.getSymbolicPos("$pc")
        return [self.formatAndUpdateReg(name,value)+' '+self.formatGrayedOut(comment)]

    def linesEFL(self,termWidth,styleChanged):
        name="EFL"
        value=run(r'printf "%08x", $eflags')
        efl=int(value,16);
        CFbit=1
        PFbit=4
        AFbit=0x10
        ZFbit=0x40
        SFbit=0x80
        TFbit=0x100
        DFbit=0x400
        OFbit=0x800
        CF = int((efl&CFbit)!=0)
        PF = int((efl&PFbit)!=0)
        AF = int((efl&AFbit)!=0)
        ZF = int((efl&ZFbit)!=0)
        SF = int((efl&SFbit)!=0)
        TF = int((efl&TFbit)!=0)
        DF = int((efl&DFbit)!=0)
        OF = int((efl&OFbit)!=0)
        result=[]
        result.append(self.formatAndUpdateFlag("CF",CF))
        result.append(self.formatAndUpdateFlag("PF",PF))
        result.append(self.formatAndUpdateFlag("AF",AF))
        result.append(self.formatAndUpdateFlag("ZF",ZF))
        result.append(self.formatAndUpdateFlag("SF",SF))
        result.append(self.formatAndUpdateFlag("TF",TF))
        result.append(self.formatAndUpdateFlag("DF",DF))
        result.append(self.formatAndUpdateFlag("OF",OF))
        result.append('')
        efl=self.formatAndUpdateReg(name,value)
        comment  = " ("
        comment += "O,"  if OF           else "NO,"
        comment += "B,"  if CF           else "AE,"
        comment += "E,"  if ZF           else "NE,"
        comment += "BE," if ZF or CF     else "A,"
        comment += "S,"  if SF           else "NS,"
        comment += "P,"  if PF           else "NP,"
        comment += "L,"  if SF!=OF       else "GE,"
        comment += "LE"  if SF!=OF or ZF else "G"
        comment += ")"
        result.append(efl+self.formatGrayedOut(comment))
        return result

    def linesSegReg(self,termWidth,styleChanged):
        regNames=["ES","CS","SS","DS","FS","GS"]
        regValues=run('printf "%04x,%04x,%04x,%04x,%04x,%04x",'+
                      '$es,$cs,$ss,$ds,$fs,$gs').split(',')
        if len(regValues)!=6:
            raise Exception("Segment registers unavailable")
        regs=dict(zip(regNames,regValues))
        registers=[]
        for name in regNames:
            value=regs[name]
            registers.append(self.formatAndUpdateReg(name,value))
        return registers

    def linesMXCSR(self,termWidth,styleChanged):
#                                 P U O Z D I
# MXCSR 00001f80  FZ 0 DZ 0  Err  0 0 0 0 0 0
#                 Rnd NEAR   Mask 1 1 1 1 1 1
        name="MXCSR"
        value=run('printf "%08x", $mxcsr')
        try: mxcsr=int(value,16)
        except: return [] # MXCSR may be unavailable if SSE isn't supported
        mxcsrLines=[]
        mxcsrLines.append("                                "+
                          self.formatRegName("P U O Z D I"))

        mainLine=(self.formatAndUpdateReg(name,value)+
                  "  "+self.formatAndUpdateReg("FZ",int((mxcsr&0x8000)!=0))+
                  " "+self.formatAndUpdateReg("DZ",int((mxcsr&0x40)!=0))+
                  "  "+self.formatRegName("Err")+"  "+
                  self.formatAndUpdateRegValue("mxcsr-PE",int((mxcsr&0x20)!=0))+" "+
                  self.formatAndUpdateRegValue("mxcsr-UE",int((mxcsr&0x10)!=0))+" "+
                  self.formatAndUpdateRegValue("mxcsr-OE",int((mxcsr&0x08)!=0))+" "+
                  self.formatAndUpdateRegValue("mxcsr-ZE",int((mxcsr&0x04)!=0))+" "+
                  self.formatAndUpdateRegValue("mxcsr-DE",int((mxcsr&0x02)!=0))+" "+
                  self.formatAndUpdateRegValue("mxcsr-IE",int((mxcsr&0x01)!=0))
                 )
        secondLine=("                "+
                    self.formatAndUpdateReg("Rnd",self.x87RoundingModeString((mxcsr>>13)&3),"SSE-")+
                    "   "+self.formatRegName("Mask")+" "+
                    self.formatAndUpdateRegValue("mxcsr-PM",int((mxcsr&0x1000)!=0))+" "+
                    self.formatAndUpdateRegValue("mxcsr-UM",int((mxcsr&0x0800)!=0))+" "+
                    self.formatAndUpdateRegValue("mxcsr-OM",int((mxcsr&0x0400)!=0))+" "+
                    self.formatAndUpdateRegValue("mxcsr-ZM",int((mxcsr&0x0200)!=0))+" "+
                    self.formatAndUpdateRegValue("mxcsr-DM",int((mxcsr&0x0100)!=0))+" "+
                    self.formatAndUpdateRegValue("mxcsr-IM",int((mxcsr&0x0080)!=0))
                 )

        mxcsrLines.append(mainLine)
        mxcsrLines.append(secondLine)
        return mxcsrLines

    def linesFPUStatusAndControl(self,termWidth,styleChanged):
        regs=run('printf "%04x,%04x,%04x",$ftag,$fstat,$fctrl').split(',')
        if(len(regs)!=3):
            raise Exception("FTR, FSR or FCR unavailable")
        ftr=regs[0]
        fsr=regs[1]
        fcr=regs[2]
        lines=[]
        lines.append(self.formatAndUpdateReg("FTR",ftr)+
                     "       "+
                     self.formatRegName("3 2 1 0")+"      "+
                     self.formatRegName("E S P U O Z D I"))
        fsrLine=self.formatAndUpdateReg("FSR",fsr);
        fsr=int(fsr,16)
        fsrLine+=("  "+self.formatRegName("Cond")+" "+
                  self.formatAndUpdateRegValue("fpu-C3",int((fsr&0x4000)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-C2",int((fsr&0x0400)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-C1",int((fsr&0x0200)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-C0",int((fsr&0x0100)!=0))+"  "+
                  self.formatRegName("Err")+" "+
                  self.formatAndUpdateRegValue("fpu-ES",int((fsr&0x0080)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-SF",int((fsr&0x0040)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-PE",int((fsr&0x0020)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-UE",int((fsr&0x0010)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-OE",int((fsr&0x0008)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-ZE",int((fsr&0x0004)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-DE",int((fsr&0x0002)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-IE",int((fsr&0x0001)!=0))
                 )
        lines.append(fsrLine+' '+self.fsrComment(fsr))

        fcrLine=self.formatAndUpdateReg("FCR",fcr)
        fcr=int(fcr,16)
        fcrLine+=("  "+
                  self.formatAndUpdateReg("Prec",self.x87RoundingModeString((fcr>>10)&3),"fpu-")+
                  ','+
                  self.formatAndUpdateRegValue("fpu-RC",self.x87PrecisionString((fcr>>8)&3))
                  )
        fcrLine+=("  "+self.formatRegName("Mask")+"    "+
                  self.formatAndUpdateRegValue("fpu-PM",int((fcr&0x0020)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-UM",int((fcr&0x0010)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-OM",int((fcr&0x0008)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-ZM",int((fcr&0x0004)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-DM",int((fcr&0x0002)!=0))+' '+
                  self.formatAndUpdateRegValue("fpu-IM",int((fcr&0x0001)!=0))
                 )
        lines.append(fcrLine)
        return lines

    def linesLastFPUOp(self,termWidth,styleChanged):
        offsetFormat = "%016lx" if self.bits==64 else "%08x"
        regs=run('printf "%04x,%04x,%04x,'+offsetFormat+','+offsetFormat+'",$fop,$fiseg,$foseg,$fioff,$fooff').split(',')
        if len(regs)!=5:
            raise Exception("Failed to get FPU last operation info")
        fop=regs[0]
        fiseg=regs[1]
        foseg=regs[2]
        fioff=regs[3]
        fooff=regs[4]
        lines=[]
        lines.append(self.formatAndUpdateReg("Last insn",fiseg,"seg-")+":"+
                     self.formatAndUpdateRegValue("off-Last insn",fioff))
        lines.append(self.formatAndUpdateReg("Last data",foseg,"seg-")+":"+
                     self.formatAndUpdateRegValue("off-Last data",fooff))
        fop=int(fop,16)
        fop1=(fop>>8)|0xd8
        fop2=fop&0xff
        fopStr = "%02x %02x" % (fop1,fop2) if fop!=0 else "00 00"
        lines.append(self.formatAndUpdateReg("Last opcode",fopStr,"fpu-"))
        return lines

    def linesFPUDataRegs(self,termWidth,styleChanged):
        ftags=int(run('printf "%04x",$ftag'),16)
        fsr=int(run('printf "%04x",$fstat'),16)
        top=(fsr>>11)&7

        regsST=[]
        for i in range(8):
            try:
                regStr=run('printf "%.21Lg",$st{:x}'.format(i))
                if regStr=="0":
                    regStr="0.0"
                elif regStr=="-0":
                    regStr="-0.0"
                elif regStr=="nan" or regStr=="-nan":
                    raise Exception("NaN")
                elif regStr=="inf":
                    regStr="+INF"
                elif regStr=="-inf":
                    regStr="-INF"
                regsST.append(regStr)
            except Exception:
                regStr=run('info reg st%x' % i)
                rawStr=re.sub(".*\(raw 0x([^)]+)\).*","\\1",regStr).rstrip()
                regsST.append(self.formatBadFloat80(rawStr))
        lines=[]
        for i in range(8):
            stNum=(i-top)&7
            name=self.formatRegName("ST%x" % stNum)
            tag=(ftags>>(2*i))&3
            tagString=self.formatAndUpdateFPUTag(i,tag)
            regValue=regsST[stNum]
            regChanged=self.checkAndUpdateChanged("fpu-R%x" % i,regValue)
            if tag!=3 or regChanged:
                value=self.formatRegValue(regValue,regChanged)
            else:
                value=self.formatGrayedOut(regValue)
            lines.append(name+' '+tagString+' '+value)
        return lines

    def lines(self,termWidth,styleChanged):
        arch=run("show arch")
        if " i386:x64-32" in arch or " i386:x86-64" in arch:
            self.bits=64
        else:
            self.bits=32
        try:
            theLines=(self.linesGPR(termWidth,styleChanged)+['']+
                      self.linesPC(termWidth,styleChanged)+[''])
            efl=self.linesEFL(termWidth,styleChanged)
            seg=self.linesSegReg(termWidth,styleChanged)
            if len(efl)<len(seg):
                raise Exception("BUG: EFL has fewer lines than segReg")
            for i in range(len(efl)):
                if i<len(seg):
                    theLines.append(efl[i]+'  '+seg[i])
                else:
                    theLines.append(efl[i])
            theLines+=['']+self.linesFPUDataRegs(termWidth,styleChanged)
            theLines+=['']+self.linesFPUStatusAndControl(termWidth,styleChanged)
            theLines+=['']+self.linesLastFPUOp(termWidth,styleChanged)
            theLines+=['']+self.linesMXCSR(termWidth,styleChanged)
            return theLines
        except Exception,e:
            return [str(e)]
