import os
import ldap3
from flask import current_app
from extensions import db
from models import Server, StatusHistory, ScheduledMaintenance

# Active Directory Configuration
AD_CONFIG = {
    'servers': ['ldap://YOUR-AD-01:389', 'ldap://YOUR-AD-02:389', 'ldap://YOUR-AD-03:389'],
    'base_dn': 'dc=vm,dc=be',
    'admin_group': 'AdminStatusDashboard',
    'bind_dn': None,
    'bind_password': None,
}

def connect_ldap(username="service@YOUR-DOMAIN", password="YourDomainPassword"):
    """Connect to LDAP server and retrieve user info if authenticated."""
    for server_url in AD_CONFIG['servers']:
        try:
            server = ldap3.Server(server_url, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, user=username, password=password, auto_bind=True)
            if conn.bound:
                if username:
                    # Fetch user details
                    search_filter = f"(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username.split('@')[0])})"
                    conn.search(
                        search_base=AD_CONFIG['base_dn'],
                        search_filter=search_filter,
                        search_scope=ldap3.SUBTREE,
                        attributes=['givenName', 'sn', 'sAMAccountName']
                    )
                    if conn.entries:
                        user_entry = conn.entries[0]
                        return conn, {
                            'first_name': user_entry.givenName.value if user_entry.givenName else '',
                            'last_name': user_entry.sn.value if user_entry.sn else '',
                            'username': user_entry.sAMAccountName.value
                        }
                    return conn, None
                return conn, None
        except ldap3.core.exceptions.LDAPException as e:
            current_app.logger.error(f"Failed to connect to {server_url}: {e}")
            continue
    return None, None

# In functions/ldap.py, modify the error logging in authenticate_user
def authenticate_user(username, password):
    """Authenticate user against Active Directory and check group membership."""
    if not username or not password:
        current_app.logger.error(
            "LDAP authentication error: Username or password missing",
            extra={'user': 'unknown', 'action': 'LDAP authentication attempt'}
        )
        return False, None
    
    if not AD_CONFIG['admin_group']:
        current_app.logger.error(
            "LDAP authentication error: AD_ADMIN_GROUP environment variable not set",
            extra={'user': username, 'action': 'LDAP authentication attempt'}
        )
        return False, None

    domain = 'vm.be'
    upn = f"{username}@{domain}"
    conn, user_info = connect_ldap(upn, password)
    if not conn:
        current_app.logger.error(
            "LDAP authentication error: Failed to connect to LDAP server",
            extra={'user': username, 'action': 'LDAP authentication attempt'}
        )
        return False, None
    
    try:
        search_filter = f"(sAMAccountName={ldap3.utils.conv.escape_filter_chars(username)})"
        conn.search(
            search_base=AD_CONFIG['base_dn'],
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=['memberOf']
        )
        
        if not conn.entries:
            current_app.logger.error(
                f"LDAP authentication error: No user found for {username}",
                extra={'user': username, 'action': 'LDAP authentication attempt'}
            )
            return False, None
        
        user_entry = conn.entries[0]
        member_of = user_entry.memberOf.values if user_entry.memberOf else []
        
        group_dn = f"CN={AD_CONFIG['admin_group']},OU=Groups,DC=vm,DC=be"
        if any(AD_CONFIG['admin_group'].lower() in group.lower() for group in member_of):
            return True, user_info
        
        group_filter = f"(&(objectClass=group)(CN={AD_CONFIG['admin_group']})(member={user_entry.dn}))"
        conn.search(
            search_base=AD_CONFIG['base_dn'],
            search_filter=group_filter,
            search_scope=ldap3.SUBTREE,
            attributes=['member']
        )
        
        return bool(conn.entries), user_info
        
    except Exception as e:
        current_app.logger.error(
            f"LDAP authentication error: {e}",
            extra={'user': username, 'action': 'LDAP authentication attempt'}
        )
        return False, None
    finally:
        if conn:
            conn.unbind()