import logging

from magen_utils_apis.dd_events_wrapper import DDEventsWrapper
from magen_logger.logger_config import LogDefaults
import os

__author__ = "Alena Lifar"
__email__ = "alifar@cisco.com"
__version__ = "0.1"
__copyright__ = "Copyright(c) 2015, Cisco Systems, Inc."
__status__ = "alpha"


datadog_options = {
        'api_key': os.environ.get('DATADOG_API_KEY'),
        'app_key': os.environ.get('DATADOG_APP_KEY')
    }


class DDIdentityEventsWrapper(DDEventsWrapper):
    none_replacer = 'Unknown'
    _known_actions = {
        'create': 'client.create',
        'update': 'client.update',
        'delete': 'client.delete',
        'client.create': 'client.create',
        'client.update': 'client.update',
        'client.delete': 'client.delete',
    }

    def __init__(self, app_name=None, magen_logger=None):
        logger = logging.getLogger(LogDefaults.default_log_name)
        logger.debug("======DD Event 22======",app_name)
        if not app_name and not super().app_tag:
            raise ValueError("app_name must be provided at least once")
        if app_name:
            super(DDIdentityEventsWrapper, self).__init__(app_name,
                                                          magen_logger or logging.getLogger(
                                                              LogDefaults.default_log_name))
        else:
            super(DDIdentityEventsWrapper, self).__init__(super().app_tag,
                                                          magen_logger or logging.getLogger(
                                                              LogDefaults.default_log_name))

    @classmethod
    def construct_event(cls, validation_data, **kwargs):
        """
        Construct event from given dictionary and kwargs
        :param validation_data: usually it is a response data from a REST API (User or Client)
        :param kwargs:
        :return: constructed event data dict
        """
        event_data = dict(
            client_id=validation_data.get('mc_id', None) or kwargs.get('mc_id', None),
            device_id=validation_data.get('device_id', None) or DDIdentityEventsWrapper.none_replacer,
            user=validation_data.get('user', None) or DDIdentityEventsWrapper.none_replacer,
            ip=validation_data.get('ip', None) or DDIdentityEventsWrapper.none_replacer,
            reason=kwargs.get('cause', None) or validation_data.get('cause', None),
            success=kwargs['success'] if 'success' in kwargs.keys() else validation_data.get('success', None),
            action=cls._known_actions[kwargs['action']] if kwargs.get('action', None) else None
        )
        return event_data