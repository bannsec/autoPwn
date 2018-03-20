
class Text:
    """
    Just a simple text box area.
    """

    def __init__(self):
        self._text = ""

    def setConsole(self,console):
        self._console = console

    def setText(self,text):
        self._text = text

    def draw(self,height,width):
        
        ret = ""
        
        # TODO: Re-work this to not line break in the middle of words
        
        # Loop through each line
        for line in self._text.split("\n"):

            # Breaking up input into multiple lines if needed
            for i in range(0,len(line),width):
                ret += line[i:i+width] + "\n"


        return ret.rstrip("\n")
