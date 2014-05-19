__author__ = 'coto'
"""
Created on June 10, 2012
@author: peta15
"""

from datetime import datetime
from wtforms import fields
from wtforms import Form
from wtforms import validators, ValidationError
from webapp2_extras.i18n import lazy_gettext as _
from webapp2_extras.i18n import ngettext, gettext
from bp_includes.lib import utils
from bp_includes.forms import UsernameMixin, NameMixin


FIELD_MAXLENGTH = 80 # intended to stop maliciously long input


class FormTranslations(object):
    def gettext(self, string):
        return gettext(string)

    def ngettext(self, singular, plural, n):
        return ngettext(singular, plural, n)

class BaseForm(Form):
    def __init__(self, request_handler):
        super(BaseForm, self).__init__(request_handler.request.POST)

    def _get_translations(self):
        return FormTranslations()


class EmailMixin(BaseForm):
    email = fields.TextField(_('Email'), [validators.Required(),
                                          validators.Length(min=8, max=FIELD_MAXLENGTH, message=_(
                                                    "Field must be between %(min)d and %(max)d characters long.")),
                                          validators.regexp(utils.EMAIL_REGEXP, message=_('Invalid email address.'))])


# ==== Forms ====

class DeleteAccountForm(BaseForm):
    password = fields.TextField(_('Password'), [validators.Required(),
                                                validators.Length(max=FIELD_MAXLENGTH, message=_(
                                                    "Field cannot be longer than %(max)d characters."))],
                                id='l_password')
    pass


class ContactForm(EmailMixin):
    name = fields.TextField(_('Name'), [validators.Required(),
                                        validators.Length(max=FIELD_MAXLENGTH, message=_(
                                                    "Field cannot be longer than %(max)d characters.")),
                                        validators.regexp(utils.NAME_LASTNAME_REGEXP, message=_(
                                                    "Name invalid. Use only letters and numbers."))])
    message = fields.TextAreaField(_('Message'), [validators.Required(), validators.Length(max=65536)])
    pass


def inbound_date_range_check(form, field):
    if (None not in (form.inbound_departure_dt.data, form.inbound_arrival_dt.data)
        and (form.inbound_departure_dt.data > form.inbound_arrival_dt.data)):
        raise ValidationError("Inbound departure time, if provided, must be before your planned arrival at Surrender.")

def outbound_date_range_check(form, field):
    if (None not in (form.outbound_departure_dt.data, form.outbound_arrival_dt.data)
        and (form.outbound_departure_dt.data > form.outbound_arrival_dt.data)):
        raise ValidationError("Outbound arrival time, if provided, must be after your planned departure from Surrender.")
        
class EditProfileForm(UsernameMixin, NameMixin):
    DT_FORMAT = '%m/%d/%Y %I:%M %p' # for use with jquery-ui
    country = fields.SelectField(_('Country'), choices=[])
    tz = fields.SelectField(_('Timezone'), choices=[])
    city = fields.TextField(_('City'))
    state = fields.TextField(_('State/Province'))
    inbound_departure_dt = fields.DateTimeField(_('Estimated departure for Surrender'), [validators.optional(), inbound_date_range_check], format=DT_FORMAT)
    inbound_arrival_dt = fields.DateTimeField(_('Estimated arrival at Surrender'), [validators.optional()], format=DT_FORMAT)
    outbound_departure_dt = fields.DateTimeField(_('Estimated departure from Surrender'), [validators.optional()], format=DT_FORMAT)
    outbound_arrival_dt = fields.DateTimeField(_('Estimated arrival at home'), [validators.optional(), outbound_date_range_check], format=DT_FORMAT)
    needs = fields.TextAreaField(_('Needs'))
    needs_met = fields.BooleanField(_('Needs met'))
    offers = fields.TextAreaField(_('Offers'))
    offers_taken = fields.BooleanField(_('Offers taken'))
    notes = fields.TextAreaField(_('Notes'))
    pass
