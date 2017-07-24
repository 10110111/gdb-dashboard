class x86_GPR(Dashboard.Module):
    "x86 general-purpose registers view"

    def label(self):
        return 'GPR'

    def lines(self,termWidth,styleChanged):
        return ["First line", "second Line"]
