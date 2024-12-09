import config as config
import logging
from LdapModify import LdapModify

GROUP_FILTER = '(objectCategory=group)'
GROUP_MEMBERS_FILTER = '(&(objectCategory=group)(cn={}))'


def get_groups_info(ldap_connect) -> list:
    # По умолчанию gidNumber, msSFU30NisDomain и msSFU30Name не назначаются новой группе
    groups_info = []
    attribute_list = ['cn', 'description', 'gidNumber', 'member']
    group_list = ldap_connect.ldap_search_s(config.BASE_DN, GROUP_FILTER, attribute_list)
    for item in group_list:
        try:
            attribute_dict = item[1]
            result_dict = {}
            for key, value in attribute_dict.items():
                result_dict.update({key: value[0].decode("utf-8")})
            if result_dict.get('gidNumber'):
                groups_info.append(result_dict)
        except IndexError:
            continue
    return groups_info


def get_group_members(ldap_connect, group_members_filter) -> list:
    users_info = []
    attribute_list = ['member']
    logging.debug(f'Base DN: {config.BASE_DN} group_members_filter: {group_members_filter}, attribute_list: {attribute_list}')
    group_member_items = ldap_connect.ldap_search_s(config.BASE_DN, group_members_filter, attribute_list)
    logging.debug(f'get_group_members: {group_member_items}')
    if group_member_items:
        try:
            user_list = group_member_items[0][1]['member']
            for user in user_list:
                users_info.append(user.decode("utf-8"))
        except (IndexError, KeyError) as error:
            logging.debug(f'Error {error}')
    return users_info


def get_user_attributes(ldap_connect, group_common_name, user_name) -> list:
    USER_NAME_PARM = 0
    user_search = ldap_connect.extract_parm(user_name, USER_NAME_PARM)
    user_base_dn = config.BASE_DN_USER.format(user_name=user_search, org_unit=group_common_name)
    logging.debug(f'Base DN: {user_base_dn}')
    result = ldap_connect.cat_search(user_base_dn)
    return result


def main():
    logging.basicConfig(level=logging.INFO)

    ldap_member_attr = 'sAMAccountName'
    attribute_list = ['cn', 'uid', 'msSFU30Name', 'msSFU30NisDomain', 'uidNumber', 'gidNumber', 'loginShell',
                      'unixHomeDirectory', ldap_member_attr]

    ldap_connect = LdapModify(config.HOSTNAME, config.USERNAME, config.PASSWORD)
    group_info = get_groups_info(ldap_connect)

    for group in group_info:
        group_common_name = group['cn']
        print(f'GROUP NAME: {group_common_name}')
        users_info = get_group_members(ldap_connect, GROUP_MEMBERS_FILTER.format(group_common_name))
        for user in users_info:
            result = get_user_attributes(ldap_connect, group_common_name , user)
            if result:
                user_dn, user_attributes = result[0]
                print(f'Атрибуты пользователя: {user_dn}:')
                for attr, values in user_attributes.items():
                    if attr in attribute_list:
                        try:
                            print(f'{attr}: {values[0].decode("utf-8")}')
                        except UnicodeDecodeError:
                            print(f'{attr}: {values[0]}')
            print('\r\n')


if __name__ == '__main__':
    main()
