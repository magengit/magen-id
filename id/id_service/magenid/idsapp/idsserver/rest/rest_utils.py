# coding=utf-8
"""REST API utilities functions"""


def check_payload(data: dict, required_fields: list):
    """
    Check payload for presented keys in data

    :param data: data to be verified
    :type data: dict
    :param required_fields: required fields to be present in payload
    :type required_fields: list

    :return: success and missing keys
    :rtype: tuple
    """
    not_present = list()
    for field in required_fields:
        if field not in data or not data[field]:
            not_present.append(field)
    return (True, None) if not not_present else (False, not_present)
