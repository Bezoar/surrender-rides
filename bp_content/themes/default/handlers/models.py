from datetime import datetime
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
    inbound_departure_dt = ndb.DateTimeProperty()
    #: User inbound arrival date
    inbound_arrival_dt = ndb.DateTimeProperty(default=datetime(2014, 6, 12, 12, 00))
    #: User outbound departure date
    outbound_departure_dt = ndb.DateTimeProperty(default=datetime(2014, 6, 16, 14, 00))
    #: User outbound arrival date
    outbound_arrival_dt = ndb.DateTimeProperty()

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

    def get_full_name(self):
        rv = ""
        if self.name and self.last_name:
            rv = self.name + " " + self.last_name
        elif self.name:
            rv = self.name
        elif self.last_name:
            rv = self.last_name
        else:
            rv = "[Anonymous user]"
        return rv
        
    def get_city_state(self):
        rv = ""
        if self.city and self.state:
            rv = self.city + ", " + self.state
        elif self.city:
            rv = self.city
        else:
            rv = self.state
        return rv

    def get_needs(self):
        rv = self.needs
        if self.needs_met and rv:
            rv = "[Needs met: %s]" % rv
        return rv

    def get_offers(self):
        rv = self.offers
        if self.offers_taken and rv:
            rv = "[Offers granted/accepted: %s]" % rv
        return rv

    def format_inbound_departure_dt(self):
        rv = ""
        if self.inbound_departure_dt:
            rv = self.inbound_departure_dt.strftime("%m/%d %I:%M%p")
        return rv

    def format_inbound_arrival_dt(self):
        rv = ""
        if self.inbound_arrival_dt:
            rv = self.inbound_arrival_dt.strftime("%m/%d %I:%M%p")
        return rv

    def format_outbound_departure_dt(self):
        rv = ""
        if self.outbound_departure_dt:
            rv = self.outbound_departure_dt.strftime("%m/%d %I:%M%p")
        return rv

    def format_outbound_arrival_dt(self):
        rv = ""
        if self.outbound_arrival_dt:
            rv = self.outbound_arrival_dt.strftime("%m/%d %I:%M%p")
        return rv
    
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

# Put here your models or extend User model from bp_includes/models.py
