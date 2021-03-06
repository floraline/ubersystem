from time import sleep

from pockets import listify
from pockets.autolog import log

import uber
from uber.amazon_ses import AmazonSES, EmailMessage  # TODO: replace this after boto adds Python 3 support
from uber.config import c


def _record_email_sent(email):
    """
    Save in our database the contents of the Email model passed in.

    We'll use this for history tracking, and to know that we shouldn't
    re-send this email because it already exists

    Note:
        This is in a separate function so we can unit test it.

    """
    with uber.models.Session() as session:
        session.add(email)


def _is_dev_email(email):
    """
    Returns True if `email` is a development email address.

    Development email addresses either end in "mailinator.com" or exist
    in the `c.DEVELOPER_EMAIL` list.
    """
    return email.endswith('mailinator.com') or c.DEVELOPER_EMAIL in email


def send_email(source, dest, subject, body, format='text', cc=(), bcc=(), model=None, ident=None):
    subject = subject.format(EVENT_NAME=c.EVENT_NAME)
    to, cc, bcc = map(listify, [dest, cc, bcc])
    ident = ident or subject
    if c.DEV_BOX:
        for xs in [to, cc, bcc]:
            xs[:] = [email for email in xs if _is_dev_email(email)]

    if c.SEND_EMAILS and to:
        msg_kwargs = {'bodyText' if format == 'text' else 'bodyHtml': body}
        message = EmailMessage(subject=subject, **msg_kwargs)
        AmazonSES(c.AWS_ACCESS_KEY, c.AWS_SECRET_KEY).sendEmail(
            source=source,
            toAddresses=to,
            ccAddresses=cc,
            bccAddresses=bcc,
            message=message)
        sleep(0.1)  # Avoid hitting rate limit
    else:
        log.error('email sending turned off, so unable to send {}', locals())

    if model and dest:
        body = body.decode('utf-8') if isinstance(body, bytes) else body
        if model == 'n/a':
            fk_kwargs = {'model': 'n/a'}
        else:
            fk_kwargs = {'fk_id': model.id, 'model': model.__class__.__name__}

        _record_email_sent(uber.models.email.Email(
            subject=subject,
            dest=','.join(listify(dest)),
            body=body,
            ident=ident,
            **fk_kwargs))


from uber.notifications.attractions import *  # noqa: F401,E402,F403
from uber.notifications.tabletop import *  # noqa: F401,E402,F403
