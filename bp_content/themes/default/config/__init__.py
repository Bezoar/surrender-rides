"""
This configuration file loads environment's specific config settings for the application.
It takes precedence over the config located in the boilerplate package.
"""

import os

from google.appengine.api import app_identity

#
# See:
# http://stackoverflow.com/questions/1916579/in-python-how-can-i-test-if-im-in-google-app-engine-sdk
# https://developers.google.com/appengine/docs/python/appidentity/
#

DEV_IDENTITY = "[unused]"
PROD_IDENTITY = "surrender-rides"

app_id = app_identity.get_application_id()
env_id = (os.environ["SERVER_SOFTWARE"]
          if "SERVER_SOFTWARE" in os.environ else "")
http_host = (os.environ["HTTP_HOST"]
             if "HTTP_HOST" in os.environ else "")

from config.common import config

if app_id.startswith("dev~") or env_id.startswith("Dev"):
    from config.localhost import config as site_config
elif app_id == DEV_IDENTITY:
    from config.stage import config as site_config
elif app_id == PROD_IDENTITY:
    from config.production import config as site_config
elif http_host == "localhost":
    # Config for local unit testing
    from config.testing import config as site_config
else:
    raise ValueError("Can't tell what kind of instance this is. Check config/__init__.py.")

config.update(site_config)
