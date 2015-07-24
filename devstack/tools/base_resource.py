import abc
import six


@six.add_metaclass(abc.ABCMeta)
class BaseResource():

    @abc.abstractmethod
    def read_endpoint():
        pass

    @abc.abstractmethod
    def delete_endpoint():
        pass

    @abc.abstractmethod
    def get_name(obj):
        pass

    @abc.abstractmethod
    def get_id(obj):
        pass

    @abc.abstractmethod
    def process_api_response(response):
        pass

    @abc.abstractmethod
    def process_db_response(response):
        pass
    
