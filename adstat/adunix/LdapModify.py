import logging

import ldap
from datetime import datetime, timedelta


class LdapModify:
    def __init__(self, hostname, username, password, trace_lvl=0):
        self.ldap_connect = ldap.initialize('ldap://'+hostname+'/', trace_level=trace_lvl)
        self.ldap_connect.simple_bind_s(username, password)
        self.scope = ldap.SCOPE_SUBTREE
        self.department = 'department'
        self.ldap_member_attr = 'sAMAccountName'
        self.ldap_search_attr = 'displayName'

    def get_member_attrs(self, base, name, user_filter, *attrs) -> dict:
        """
            Возвращает словарь с ключами: self.ldap_member_attr, self.ldap_search_attr + attrs
        """
        filter_exp = user_filter.format(name)
        attr_list = [attr for attr in attrs]

        # Без этой строки поиск не работает
        attr_list.append(self.ldap_member_attr)

        results_dict = {self.ldap_search_attr: name}
        try:
            results = self.ldap_connect.search_s(base, self.scope, filter_exp, attr_list)
        except ldap.NO_SUCH_OBJECT:
            return results_dict

        if results:
            for attr in attr_list:
                results_dict[attr] = self.check_attr(attr, results)
        return results_dict

    @staticmethod
    def check_attr(attr: str, results: list) -> str:
        try:
            result = results[0][1][attr][0]
            result = result.decode("utf-8")
            return result
        except (IndexError, KeyError):
            return ''

    def modify_department(self, dn, department_description):
        if not dn or not department_description:
            return False

        mod_list = [
            (ldap.MOD_REPLACE, self.department, department_description.encode('utf-8')),
        ]
        print('Modify dept to {}'.format(department_description))
        self.ldap_connect.modify_s(dn, mod_list)

    def remove_value_of_parameters(self, dn, *parameters):
        mod_list = [(ldap.MOD_DELETE, parm, None) for parm in parameters]
        try:
            self.ldap_connect.modify_s(dn, mod_list)
        except ldap.NO_SUCH_ATTRIBUTE as err:
            print('Error delete parameters {}: {}'.format(parameters, err))

    def get_users(self, base_dn, user_filter, attribute_list):
        return self.ldap_connect.search_s(base_dn, self.scope, user_filter, attribute_list)

    def ldap_search_s(self, base_dn, search_filter, attribute_list):
        result = ''
        try:
            result = self.ldap_connect.search_s(base_dn, self.scope, search_filter, attribute_list)
        except ldap.NO_SUCH_OBJECT as err:
            logging.info(f'Error: {err}')
        return result

    def cat_search(self, base_dn):
        result = None
        try:
            result = self.ldap_connect.search_s(base_dn, ldap.SCOPE_BASE)
        except ldap.NO_SUCH_OBJECT as err:
            logging.debug(f'Error: {err}')
        return result

    def get_groups(self, base_dn, group_filter, attribute_list):
        return self.ldap_connect.search_s(base_dn, self.scope, group_filter, attribute_list)

    @staticmethod
    def groups_result_value(result, name):
        try:
            value = result[1][name][0].decode("utf-8")
            return value
        except (IndexError, KeyError):
            return ''

    def parse_dn(self, dn_user_name):
        user_name_parm = 0
        user_ou_parm = 2
        dn_user_name = dn_user_name.decode("utf-8")
        user_name = self.extract_parm(dn_user_name, user_name_parm)
        user_ou = self.extract_parm(dn_user_name, user_ou_parm)
        return user_name, user_ou

    @staticmethod
    def extract_parm(name, parm):
        try:
            value = name.split(',')[parm]
            value = value.split('=')[1]
        except IndexError as err:
            print('Cannot extract parm: {}'.format(err))
            return ''
        return value

    def make_members_dict(self, base_dn_ou_filter, user_filter, members, *attrs):
        users_dict = {}
        for member in members:
            user_name, user_ou = self.parse_dn(member)
            base = base_dn_ou_filter.format(user_ou)
            member_record = self.get_member_attrs(base, user_name, user_filter, *attrs)
            if member_record:
                try:
                    users_dict[member_record[self.ldap_member_attr]] = member_record
                except (KeyError, IndexError):
                    pass
        return users_dict

    @staticmethod
    def ldap2datetime(ts):
        ts = int(ts)
        return datetime(1601, 1, 1) + timedelta(seconds=ts / 10000000)

    def __del__(self):
        self.ldap_connect.unbind_s()
