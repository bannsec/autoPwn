
class Banner:
    """
    Just a silly banner class
    """

    def __init__(self):
        pass

    def setConsole(self,console):
        self._console = console

    def draw(self,height,width):

        # If we're in too small of an area to actually draw, just type
        if height < 7 or width < 117:
            return "autoPwn -- {0}".format(url)

        else:
            return banner

url = '(c) https://github.com/Owlz/autoPwn'

banner = r""" ________  ___  ___  _________  ________  ________  ___       __   ________      
|\   __  \|\  \|\  \|\___   ___\\   __  \|\   __  \|\  \     |\  \|\   ___  \    
\ \  \|\  \ \  \\\  \|___ \  \_\ \  \|\  \ \  \|\  \ \  \    \ \  \ \  \\ \  \   
 \ \   __  \ \  \\\  \   \ \  \ \ \  \\\  \ \   ____\ \  \  __\ \  \ \  \\ \  \  
  \ \  \ \  \ \  \\\  \   \ \  \ \ \  \\\  \ \  \___|\ \  \|\__\_\  \ \  \\ \  \ 
   \ \__\ \__\ \_______\   \ \__\ \ \_______\ \__\    \ \____________\ \__\\ \__\
    \|__|\|__|\|_______|    \|__|  \|_______|\|__|     \|____________|\|__| \|__| {0}""".format(url)
