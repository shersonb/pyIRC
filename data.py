
class Data:
    """Data is a generic storage interface for addons which need to persist data.

    Addons can access Data through the Connection.data attribute. Each addon
    should add its own attribute to Data to serve as a namespace. For example,
    the Foo addon might store a dict as such:

        Connection.data.foo = dict()

    Data doesn't persist anything on its own but instead relies on a persistence
    addon to handle the onDataSave and onDataLoad events.

    Data fires an onDataLoaded event to inform addons that new data may be available.
    """

    def __init__(self, context, **kwargs):
        """Create a Data for the given Connection context.

        Optionally pass in a dict of values to load.
        """
        self.__dict__ = kwargs
        self.context = context

    def set_data(self, values):
        """Replace all values in this Data with the given dict."""
        contex = self.context
        self.__dict__ = values
        self.context = context
        self.context.fireEvent([('onDataLoaded', dict(data=self), False)])

    def merge(self, values):
        """Merge a dictionary into this Data."""
        for k, v, in values.iteritems():
            setattr(self, k, v)
        self.context.fireEvent([('onDataLoaded', dict(data=self), False)])

    def save(self):
        """Trigger the onDataSave event."""
        data = self.__dict__
        del data['context']
        self.context.fireEvent([('onDataSave', dict(data=self, values=data), False)])

