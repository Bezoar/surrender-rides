import logging
from webapp2_extras.appengine.auth.models import User
from google.appengine.ext import ndb
from bp_includes.models import SocialUser

class User(User):
    """
    Universal user model. Can be used with App Engine's default users API,
    own auth or third party authentication methods (OpenID, OAuth etc).
    """

    #: Creation date.
    created = ndb.DateTimeProperty(auto_now_add=True)
    #: Modification date.
    updated = ndb.DateTimeProperty(auto_now=True)
    #: User defined unique name, also used as key_name.
    # Not used by OpenID
    username = ndb.StringProperty()
    #: User Name
    name = ndb.StringProperty()
    #: User Last Name
    last_name = ndb.StringProperty()
    #: User email
    email = ndb.StringProperty()
    #: Hashed password. Only set for own authentication.
    # Not required because third party authentication
    # doesn't use password.
    password = ndb.StringProperty()
    #: User Country
    country = ndb.StringProperty(default='US')

    #: User City
    city = ndb.StringProperty()
    #: User State/Province
    state = ndb.StringProperty()

    #: User inbound departure date
    inbound_departure_date = ndb.DateTimeProperty()
    #: User inbound arrival date
    inbound_arrival_date = ndb.DateTimeProperty()
    #: User outbound departure date
    outbound_departure_date = ndb.DateTimeProperty()
    #: User outbound arrival date
    outbound_arrival_date = ndb.DateTimeProperty()

    #: User needs
    needs = ndb.StringProperty()
    #: User needs met
    needs_met = ndb.BooleanProperty(default=False)

    #: User offers
    offers = ndb.StringProperty()
    #: User offers taken
    offers_taken = ndb.BooleanProperty(default=False)

    #: Notes
    notes = ndb.StringProperty()

    #: User TimeZone
    tz = ndb.StringProperty(default='America/Los_Angeles')
    #: Account activation verifies email
    activated = ndb.BooleanProperty(default=False)

    def put(self):
        if not self.country:
            self.country = 'US'
        if not self.tz:
            self.tz = 'America/Los_Angeles'
        super(User, self).put()
        
    @classmethod
    def get_by_email(cls, email):
        """Returns a user object based on an email.

        :param email:
            String representing the user email. Examples:

        :returns:
            A user object.
        """
        return cls.query(cls.email == email).get()

    @classmethod
    def create_resend_token(cls, user_id):
        entity = cls.token_model.create(user_id, 'resend-activation-mail')
        return entity.token

    @classmethod
    def validate_resend_token(cls, user_id, token):
        return cls.validate_token(user_id, 'resend-activation-mail', token)

    @classmethod
    def delete_resend_token(cls, user_id, token):
        cls.token_model.get_key(user_id, 'resend-activation-mail', token).delete()

    def get_social_providers_names(self):
        social_user_objects = SocialUser.get_by_user(self.key)
        result = []
#        import logging
        for social_user_object in social_user_objects:
#            logging.error(social_user_object.extra_data['screen_name'])
            result.append(social_user_object.provider)
        return result

    def get_social_providers_info(self):
        providers = self.get_social_providers_names()
        result = {'used': [], 'unused': []}
        for k,v in SocialUser.PROVIDERS_INFO.items():
            if k in providers:
                result['used'].append(v)
            else:
                result['unused'].append(v)
        return result
