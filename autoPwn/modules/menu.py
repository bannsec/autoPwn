
class Menu:
    """
    Create a basic menu. In actuality, this just basically is a formatted text area. Oh well.
    """

    def __init__(self,title="Menu"):
        self._items = []
        self._title = title

    def setConsole(self,console):
        self._console = console

    def addItem(self,key,value):
        """
        Adds a menu item. For instance:
            key) value
        """
        self._items.append({
            "key": key,
            "value": value
        })

    def draw(self,height,width):

        # If we're in too small of an area to actually draw, just type
        if height < len(self._items) + 3:
            return "Error: Menu space too small. Increase size to view."

        ret = self._title + "\n"
        ret += "~"*width + "\n"
        
        for item in self._items:
            ret += "{0}) {1}\n".format(item['key'],item['value'])
        
        return ret
        

