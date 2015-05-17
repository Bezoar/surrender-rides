# -*- coding: utf-8 -*-

"""
    A real simple app for using webapp2 with auth and session.

    It just covers the basics. Creating a user, login, logout
    and a decorator for protecting certain handlers.

    Routes are setup in routes.py and added in main.py
"""
# standard library imports
import logging
from datetime import datetime
# related third party imports
import webapp2
from google.appengine.ext import ndb
from google.appengine.api import taskqueue
from webapp2_extras.auth import InvalidAuthIdError, InvalidPasswordError
from webapp2_extras.i18n import gettext as _
from bp_includes.external import httpagentparser
# local application/library specific imports
import bp_includes.lib.i18n as i18n
from bp_includes.lib.basehandler import BaseHandler
from bp_includes.lib.decorators import user_required
from bp_includes.lib import captcha, utils
from bp_includes.lib.jinja_bootstrap import generate_csrf_token
import bp_includes.models as models_boilerplate
from bp_includes.handlers import RegisterBaseHandler
import forms as forms

class ContactHandler(BaseHandler):
    """
    Handler for Contact Form
    """

    def get(self):
        """ Returns a simple HTML for contact form """
        
        if self.user:
            user_info = self.user_model.get_by_id(long(self.user_id))
            if user_info.name or user_info.last_name:
                self.form.name.data = user_info.name + " " + user_info.last_name
            if user_info.email:
                self.form.email.data = user_info.email
        params = {
            "exception": self.request.get('exception')
        }

        return self.render_template('contact.html', **params)

    def post(self):
        """ validate contact form """

        if not self.form.validate():
            return self.get()
        remote_ip = self.request.remote_addr
        city = i18n.get_city_code(self.request)
        region = i18n.get_region_code(self.request)
        country = i18n.get_country_code(self.request)
        coordinates = i18n.get_city_lat_long(self.request)
        user_agent = self.request.user_agent
        exception = self.request.POST.get('exception')
        name = self.form.name.data.strip()
        email = self.form.email.data.lower()
        message = self.form.message.data.strip()
        template_val = {}

        try:
            # parsing user_agent and getting which os key to use
            # windows uses 'os' while other os use 'flavor'
            ua = httpagentparser.detect(user_agent)
            _os = ua.has_key('flavor') and 'flavor' or 'os'

            operating_system = str(ua[_os]['name']) if "name" in ua[_os] else "-"
            if 'version' in ua[_os]:
                operating_system += ' ' + str(ua[_os]['version'])
            if 'dist' in ua:
                operating_system += ' ' + str(ua['dist'])

            browser = str(ua['browser']['name']) if 'browser' in ua else "-"
            browser_version = str(ua['browser']['version']) if 'browser' in ua else "-"

            template_val = {
                "name": name,
                "email": email,
                "ip": remote_ip,
                "city": city,
                "region": region,
                "country": country,
                "coordinates": coordinates,

                "browser": browser,
                "browser_version": browser_version,
                "operating_system": operating_system,
                "message": message
            }
        except Exception as e:
            logging.error("error getting user agent info: %s" % e)

        try:
            subject = _("Contact") + " " + self.app.config.get('app_name')
            # exceptions for error pages that redirect to contact
            if exception != "":
                subject = "{} (Exception error: {})".format(subject, exception)

            body_path = "emails/contact.txt"
            body = self.jinja2.render_template(body_path, **template_val)

            email_url = self.uri_for('taskqueue-send-email')
            taskqueue.add(url=email_url, params={
                'to': self.app.config.get('contact_recipient'),
                'subject': subject,
                'body': body,
                'sender': self.app.config.get('contact_sender'),
            })

            message = _('Your message was sent successfully.')
            self.add_message(message, 'success')
            return self.redirect_to('contact')

        except (AttributeError, KeyError), e:
            logging.error('Error sending contact form: %s' % e)
            message = _('Error sending the message. Please try again later.')
            self.add_message(message, 'error')
            return self.redirect_to('contact')

    @webapp2.cached_property
    def form(self):
        return forms.ContactForm(self)


class SecureRequestHandler(BaseHandler):
    """
    Only accessible to users that are logged in
    """

    @user_required
    def get(self, **kwargs):
        user_session = self.user
        user_session_object = self.auth.store.get_session(self.request)

        user_info = self.user_model.get_by_id(long(self.user_id))
        user_info_object = self.auth.store.user_model.get_by_auth_token(
            user_session['user_id'], user_session['token'])

        try:
            params = {
                "user_session": user_session,
                "user_session_object": user_session_object,
                "user_info": user_info,
                "user_info_object": user_info_object,
                "userinfo_logout-url": self.auth_config['logout_url'],
            }
            return self.render_template('secure_zone.html', **params)
        except (AttributeError, KeyError), e:
            return "Secure zone error:" + " %s." % e


class DeleteAccountHandler(BaseHandler):

    @user_required
    def get(self, **kwargs):
        chtml = captcha.displayhtml(
            public_key=self.app.config.get('captcha_public_key'),
            use_ssl=(self.request.scheme == 'https'),
            error=None)
        if self.app.config.get('captcha_public_key') == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE" or \
                        self.app.config.get('captcha_private_key') == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE":
            chtml = '<div class="alert alert-error"><strong>Error</strong>: You have to ' \
                    '<a href="http://www.google.com/recaptcha/whyrecaptcha" target="_blank">sign up ' \
                    'for API keys</a> in order to use reCAPTCHA.</div>' \
                    '<input type="hidden" name="recaptcha_challenge_field" value="manual_challenge" />' \
                    '<input type="hidden" name="recaptcha_response_field" value="manual_challenge" />'
        params = {
            'captchahtml': chtml,
        }
        return self.render_template('delete_account.html', **params)

    def post(self, **kwargs):
        challenge = self.request.POST.get('recaptcha_challenge_field')
        response = self.request.POST.get('recaptcha_response_field')
        remote_ip = self.request.remote_addr

        cResponse = captcha.submit(
            challenge,
            response,
            self.app.config.get('captcha_private_key'),
            remote_ip)

        if cResponse.is_valid:
            # captcha was valid... carry on..nothing to see here
            pass
        else:
            _message = _('Wrong image verification code. Please try again.')
            self.add_message(_message, 'error')
            return self.redirect_to('delete-account')

        if not self.form.validate() and False:
            return self.get()
        password = self.form.password.data.strip()

        try:

            user_info = self.user_model.get_by_id(long(self.user_id))
            auth_id = "own:%s" % user_info.username
            password = utils.hashing(password, self.app.config.get('salt'))

            try:
                # authenticate user by its password
                user = self.user_model.get_by_auth_password(auth_id, password)
                if user:
                    # Delete Social Login
                    for social in models_boilerplate.SocialUser.get_by_user(user_info.key):
                        social.key.delete()

                    user_info.key.delete()

                    ndb.Key("Unique", "User.username:%s" % user.username).delete_async()
                    ndb.Key("Unique", "User.auth_id:own:%s" % user.username).delete_async()
                    ndb.Key("Unique", "User.email:%s" % user.email).delete_async()

                    #TODO: Delete UserToken objects

                    self.auth.unset_session()

                    # display successful message
                    msg = _("The account has been successfully deleted.")
                    self.add_message(msg, 'success')
                    return self.redirect_to('home')

            except (InvalidAuthIdError, InvalidPasswordError), e:
                # Returns error message to self.response.write in
                # the BaseHandler.dispatcher
                message = _("Incorrect password! Please enter your current password to change your account settings.")
                self.add_message(message, 'error')
            return self.redirect_to('delete-account')

        except (AttributeError, TypeError), e:
            login_error_message = _('Your session has expired.')
            self.add_message(login_error_message, 'error')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        return forms.DeleteAccountForm(self)


class EditProfileHandler(BaseHandler):
    """
    Handler for Edit User Profile
    """

    @user_required
    def get(self):
        """ Returns a simple HTML form for edit profile """

        params = {}
        if self.user:
            user_info = self.user_model.get_by_id(long(self.user_id))
            self.form.username.data = user_info.username
            self.form.name.data = user_info.name
            self.form.last_name.data = user_info.last_name
            self.form.country.data = user_info.country
            self.form.tz.data = user_info.tz

            # New fields we added
            for fldname in ('city', 'state',
                            'inbound_departure_dt',
                            'inbound_arrival_dt',
                            'outbound_departure_dt',
                            'outbound_arrival_dt',
                            'needs', 'needs_met',
                            'offers', 'offers_taken',
                            'notes'):
                getattr(self.form, fldname).data = getattr(user_info, fldname)
            
            providers_info = user_info.get_social_providers_info()
            if not user_info.password:
                params['local_account'] = False
            else:
                params['local_account'] = True
            params['used_providers'] = providers_info['used']
            params['unused_providers'] = providers_info['unused']
            params['country'] = user_info.country
            params['tz'] = user_info.tz

        return self.render_template('edit_profile.html', **params)

    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            return self.get()

        username = self.form.username.data.lower()
        name = self.form.name.data.strip()
        last_name = self.form.last_name.data.strip()
        country = self.form.country.data
        tz = self.form.tz.data

        new_values = {
            'username': username,
            'name': name,
            'last_name': last_name,
            'country': country,
            'tz': tz,

            # New fields we added
            'city': self.form.city.data.strip(),
            'state': self.form.state.data.strip(),
            'inbound_departure_dt': self.form.inbound_departure_dt.data,
            'inbound_arrival_dt': self.form.inbound_arrival_dt.data,
            'outbound_departure_dt': self.form.outbound_departure_dt.data,
            'outbound_arrival_dt': self.form.outbound_arrival_dt.data,
            'needs': self.form.needs.data.strip(),
            'needs_met': self.form.needs_met.data,
            'offers': self.form.offers.data.strip(),
            'offers_taken': self.form.offers_taken.data,
            'notes': self.form.notes.data.strip()
            }

        try:
            user_info = self.user_model.get_by_id(long(self.user_id))

            try:
                message = ''
                # update username if it has changed and it isn't already taken
                if username != user_info.username:
                    user_info.unique_properties = ['username', 'email']
                    uniques = [
                        'User.username:%s' % username,
                        'User.auth_id:own:%s' % username,
                    ]
                    # Create the unique username and auth_id.
                    success, existing = Unique.create_multi(uniques)
                    if success:
                        # free old uniques
                        Unique.delete_multi(
                            ['User.username:%s' % user_info.username, 'User.auth_id:own:%s' % user_info.username])
                        # The unique values were created, so we can save the user.
                        user_info.username = username
                        user_info.auth_ids[0] = 'own:%s' % username
                        message += _('Your new username is <strong>{}</strong>').format(username)

                    else:
                        message += _(
                            'The username <strong>{}</strong> is already taken. Please choose another.').format(
                            username)
                        # At least one of the values is not unique.
                        self.add_message(message, 'error')
                        return self.get()
                for (k, v) in new_values.iteritems():
                    setattr(user_info, k, v)
                user_info.put()
                message += " " + _('Thanks, your settings have been saved.')
                self.add_message(message, 'success')
                return self.redirect_to('home')

            except (AttributeError, KeyError, ValueError), e:
                import traceback
                logging.error('Error updating profile: (%s) %s' % (e.__class__.__name__, e))
                logging.error('Traceback: \n'+traceback.format_exc())
                message = _('Unable to update profile. Please try again later.')
                self.add_message(message, 'error')
                return self.get()

        except (AttributeError, TypeError), e:
            login_error_message = _('Your session has expired.')
            self.add_message(login_error_message, 'error')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        f = forms.EditProfileForm(self)
        logging.info("EditProfileHandler.form is a(n) %s" % f.__class__.__name__)
        f.country.choices = self.countries_tuple
        f.tz.choices = self.tz
        return f

class SurrenderRegisterHandler(BaseHandler):
    """
    Handler for Sign Up Users
    """

    def get(self):
        """ Returns a simple HTML form for create a new user """

        if self.user:
            self.redirect_to('home')
        params = {}
        return self.render_template('surrender_register.html', **params)

    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            return self.get()
        username = self.form.username.data.lower()
        name = self.form.name.data.strip()
        last_name = self.form.last_name.data.strip()
        email = self.form.email.data.lower()
        password = self.form.password.data.strip()
        country = self.form.country.data
        city = self.form.city.data
        state = self.form.state.data
        tz = self.form.tz.data

        # Password to SHA512
        password = utils.hashing(password, self.app.config.get('salt'))

        # Passing password_raw=password so password will be hashed
        # Returns a tuple, where first value is BOOL.
        # If True ok, If False no new user is created
        unique_properties = ['username', 'email']
        auth_id = "own:%s" % username
        user = self.auth.store.user_model.create_user(
            auth_id, unique_properties, password_raw=password,
            username=username, name=name, last_name=last_name, email=email,
            city=city, state=state,
            ip=self.request.remote_addr, country=country, tz=tz
        )

        if not user[0]: #user is a tuple
            if "username" in str(user[1]):
                message = _(
                    'Sorry, The username <strong>{}</strong> is already registered.').format(username)
            elif "email" in str(user[1]):
                message = _('Sorry, The email <strong>{}</strong> is already registered.').format(email)
            else:
                message = _('Sorry, The user is already registered.')
            self.add_message(message, 'error')
            return self.redirect_to('register')
        else:
            # User registered successfully
            # But if the user registered using the form, the user has to check their email to activate the account ???
            try:
                if not user[1].activated:
                    # send email
                    subject = _("%s Account Verification" % self.app.config.get('app_name'))
                    confirmation_url = self.uri_for("account-activation",
                                                    user_id=user[1].get_id(),
                                                    token=self.user_model.create_auth_token(user[1].get_id()),
                                                    _full=True)
                    logging.info("*** confirmation_url is %s" % confirmation_url)
                    # load email's template
                    template_val = {
                        "app_name": self.app.config.get('app_name'),
                        "username": username,
                        "confirmation_url": confirmation_url,
                        "support_url": self.uri_for("contact", _full=True)
                    }
                    body_path = "emails/account_activation.txt"
                    body = self.jinja2.render_template(body_path, **template_val)

                    email_url = self.uri_for('taskqueue-send-email')
                    taskqueue.add(url=email_url, params={
                        'to': str(email),
                        'subject': subject,
                        'body': body,
                    })

                    message = _('You were successfully registered. '
                                'Please check your email to activate your account.')
                    self.add_message(message, 'success')
                    return self.redirect_to('home')

                # If the user didn't register using registration form ???
                db_user = self.auth.get_user_by_password(user[1].auth_ids[0], password)

                # Check Twitter association in session
                twitter_helper = twitter.TwitterAuth(self)
                twitter_association_data = twitter_helper.get_association_data()
                if twitter_association_data is not None:
                    if models.SocialUser.check_unique(user[1].key, 'twitter', str(twitter_association_data['id'])):
                        social_user = models.SocialUser(
                            user=user[1].key,
                            provider='twitter',
                            uid=str(twitter_association_data['id']),
                            extra_data=twitter_association_data
                        )
                        social_user.put()

                #check Facebook association
                fb_data = json.loads(self.session['facebook'])
                if fb_data is not None:
                    if models.SocialUser.check_unique(user.key, 'facebook', str(fb_data['id'])):
                        social_user = models.SocialUser(
                            user=user.key,
                            provider='facebook',
                            uid=str(fb_data['id']),
                            extra_data=fb_data
                        )
                        social_user.put()

                #check LinkedIn association
                li_data = json.loads(self.session['linkedin'])
                if li_data is not None:
                    if models.SocialUser.check_unique(user.key, 'linkedin', str(li_data['id'])):
                        social_user = models.SocialUser(
                            user=user.key,
                            provider='linkedin',
                            uid=str(li_data['id']),
                            extra_data=li_data
                        )
                        social_user.put()

                message = _('Welcome <strong>{}</strong>, you are now logged in.').format(username)
                self.add_message(message, 'success')
                return self.redirect_to('home')
            except (AttributeError, KeyError), e:
                logging.error('Unexpected error creating the user %s: %s' % (username, e ))
                message = _('Unexpected error creating the user %s' % username)
                self.add_message(message, 'error')
                return self.redirect_to('home')

    @webapp2.cached_property
    def form(self):
        logging.info("SurrenderRegisterHandler.form()")
        try:
            f = forms.SurrenderRegisterForm(self)
            f.country.choices = self.countries_tuple
            f.tz.choices = self.tz
            logging.info("SurrenderRegisterHandler.form() returning %s" % f)
            return f
        except Exception, e:
            logging.error("Exception while creating form object for registration: (%s) %s"
                          % (e.__class__.__name__, e))
            raise

class ListSharesHandler(BaseHandler):
    @user_required
    def get(self):
        params = {}
        users = [u for u in self.user_model.query().fetch(None)
                 if (u.activated and u.get_full_name() != '[Anonymous user]')]
        params['users'] = users
        params['logged_in_user_id'] = self.user_id

        # Check our profile for completeness.
        me = self.user_model.get_by_id(long(self.user_id))
        if ((me.get_full_name == '[Anonymous user]') or
            not me.city or not me.state):
            warning_msg = 'Please <a href="/settings/profile">complete your profile</a>, so that others can see where you\'re coming from, and what you need/have for the event.'
            self.add_message(warning_msg, 'error')
            return self.redirect_to('edit-profile')
        
        return self.render_template('share_list.html', **params)

class ViewShareDetailHandler(BaseHandler):
    @user_required
    def get(self):
        params = {}
        target_user_id = int(self.request.get('user_id', '0'))
        if not target_user_id:
            message = _('User id unavailable. Please try again later.')
            self.add_message(message, 'error')
            return self.redirect_to('show-listings')
        if int(self.user_id) == target_user_id:
            # Viewing logged-in user's profile. Go to profile edit page instead.
            return self.redirect_to('edit-profile')
        u = self.user_model.get_by_id(target_user_id)
        if not u:
            message = _('Could not find user. Please try again later.')
            self.add_message(message, 'error')
            return self.redirect_to('show-listings')
        params['target_user'] = u

        # Check our profile for completeness.
        me = self.user_model.get_by_id(long(self.user_id))
        if ((me.get_full_name == '[Anonymous user]') or
            not me.city or not me.state):
            warning_msg = 'Please <a href="/settings/profile">complete your profile</a>, so that others can see where you\'re coming from, and what you need/have for the event.'
            self.add_message(warning_msg, 'error')
            return self.redirect_to('edit-profile')
        return self.render_template('share_detail.html', **params)

class SendMessageHandler(BaseHandler):
    @user_required
    def post(self):
        subj = self.request.get('subject', '')
        msg = self.request.get('message', '')
        dest_id = self.request.get('dest_id', '')
        dest_name = self.request.get('dest_name', '').strip()
        if not dest_name:
            dest_name = "Rideshare User"
        csrf_token = self.request.get('_csrf_token', '')
        
        try:
            logging.debug("*** subject: %s / message: %s / dest_id: %s / dest_name: %s" % (subj, msg, dest_id, dest_name))
            if csrf_token != generate_csrf_token():
                raise ValueError("CSRF token could not be confirmed. Cannot send message.")
            source_u = self.user_model.get_by_id(int(self.user_id))
            if not source_u:
                raise ValueError("Could not validate source user.")
            u = self.user_model.get_by_id(int(dest_id))
            if not u:
                raise ValueError("Could not find destination user.")
            dest_email = u.email
            email_url = "/taskqueue-send-email/"
            params = {
                'source_name': source_u.get_full_name(),
                'source_email': source_u.email,
                'source_user_id': source_u.key.id(),
                'subject': subj,
                'message': msg,
                'city': i18n.get_city_code(self.request),
                'region': i18n.get_region_code(self.request).upper(),
                'country': i18n.get_country_code(self.request),
                'app_name': self.app.config.get("app_name")
                }
            msg_tmpl = "emails/user_message.txt"
            msg_body = self.jinja2.render_template(msg_tmpl, **params)
            taskqueue.add(url=email_url, params={
                'to': dest_name + (" <%s>" % dest_email),
                'subject': "[Surrender Rideshare] "+subj,
                'body': msg_body,
                'sender': "%s via Surrender Rideshare <%s>" % (source_u.get_full_name(), source_u.email),
            })
        except Exception, e:
            logging.error("Exception when trying to send message: (%s) %s" % (e.__class__.__name__, e))
            self.error(500)
        

class SurrenderHomeRequestHandler(RegisterBaseHandler):
    """
    Handler to show the home page
    """

    def get(self):
        """ Returns a simple HTML form for home """
        params = {}
        # If we're logged in but our profile is incomplete,
        # redirect to the profile edit page.
        if self.user_id:
            me = self.user_model.get_by_id(long(self.user_id))
            if ((me.get_full_name == '[Anonymous user]') or
                not me.city or not me.state):
                warning_msg = 'Please <a href="/settings/profile">complete your profile</a>, so that others can see where you\'re coming from, and what you need/have for the event.'
                self.add_message(warning_msg, 'error')
                return self.redirect_to('edit-profile')
        return self.render_template('home.html', **params)
