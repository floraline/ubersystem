from datetime import datetime

from sqlalchemy import func, or_
from pockets import listify

from uber.automated_emails_server import AutomatedEmail, SendAllAutomatedEmailsJob
from uber.config import c
from uber.decorators import ajax, all_renderable, csrf_protected, csv_file, render_empty
from uber.errors import HTTPRedirect
from uber.models import AdminAccount, ApprovedEmail, Attendee, Email, Group
from uber.notifications import send_email
from uber.utils import get_page


@all_renderable(c.PEOPLE)
class Root:
    def index(self, session, page='1', search_text=''):
        emails = session.query(Email).order_by(Email.when.desc())
        search_text = search_text.strip()
        if search_text:
            emails = emails.icontains(Email.dest, search_text)
        return {
            'page': page,
            'emails': get_page(page, emails),
            'count': emails.count(),
            'search_text': search_text
        }

    def sent(self, session, **params):
        return {'emails': session.query(Email).filter_by(**params).order_by(Email.when).all()}
    sent.restricted = [c.PEOPLE, c.REG_AT_CON]

    def pending(self, session, message=''):
        automated_emails = []
        last_job_completed = SendAllAutomatedEmailsJob.last_result.get('completed', False)
        categories_results = SendAllAutomatedEmailsJob.last_result.get('categories', None)

        count_query = session.query(Email.ident, func.count(Email.ident)).group_by(Email.ident)
        sent_email_counts = {c[0]: c[1] for c in count_query.all()}

        for automated_email in AutomatedEmail.instances.values():
            category_results = categories_results.get(automated_email.ident, None) if categories_results else None
            unsent_because_unapproved = category_results.get('unsent_because_unapproved', 0) if category_results else 0

            automated_emails.append({
                'automated_email': automated_email,
                'num_sent': sent_email_counts.get(automated_email.ident, 0),
                'unsent_because_unapproved': unsent_because_unapproved if last_job_completed else '_'
            })

        return {
            'message': message,
            'automated_emails': automated_emails,
            'last_job_completed': last_job_completed
        }

    def pending_examples(self, session, ident):
        count = 0
        examples = []
        email = AutomatedEmail.instances[ident]
        example = render_empty('emails/' + email.template)
        for x in AutomatedEmail.queries[email.model](session):
            if email.filters_run(x):
                count += 1
                url = {
                    Group: '../groups/form?id={}',
                    Attendee: '../registration/form?id={}'
                }.get(x.__class__, '').format(x.id)
                if len(examples) < 10:
                    examples.append([url, email.render(x).decode('utf-8')])

        return {
            'count': count,
            'example': example,
            'examples': examples,
            'subject': email.subject,
        }

    def test_email(self, session, subject=None, body=None, from_address=None, to_address=None, **params):
        """
        Testing only: send a test email as a system user
        """

        output_msg = ""

        if subject and body and from_address and to_address:
            send_email(from_address, to_address, subject, body)
            output_msg = "RAMS has attempted to send your email."

        right_now = str(datetime.now())

        return {
            'from_address': from_address or c.STAFF_EMAIL,
            'to_address': (
                to_address or
                ("goldenaxe75t6489@mailinator.com" if c.DEV_BOX else AdminAccount.admin_email())
                or ""),
            'subject':  c.EVENT_NAME_AND_YEAR + " test email " + right_now,
            'body': body or "ignore this email, <b>it is a test</b> of the <u>RAMS email system</u> " + right_now,
            'message': output_msg,
        }

    @ajax
    def resend_email(self, session, id):
        """
        Resend a particular email to the model's current email address.

        This is useful for if someone had an invalid email address and did not receive an automated email.
        """

        email = session.email(id)
        if email:
            # If this was an automated email, we can send out an updated template with the correct 'from' address
            if email.ident in AutomatedEmail.instances:
                email_category = AutomatedEmail.instances[email.ident]
                sender = email_category.sender
                body = email_category.render(email.fk)
            else:
                sender = c.ADMIN_EMAIL
                body = email.html

            try:
                send_email(sender, email.rcpt_email, email.subject, body, model=email.fk, ident=email.ident)
            except Exception:
                return {'success': False, 'message': 'Email not sent: unknown error.'}
            else:
                return {'success': True, 'message': 'Email resent.'}
        return {'success': False, 'message': 'Email not sent: no email found with that ID.'}

    @csrf_protected
    def approve(self, session, ident):
        session.add(ApprovedEmail(ident=ident))
        raise HTTPRedirect('pending?message={}', 'Email approved and will be sent out shortly')

    def emails_by_interest(self, message=''):
        return {
            'message': message
        }

    @csv_file
    def emails_by_interest_csv(self, out, session, **params):
        """
        Generate a list of emails of attendees who match one of c.INTEREST_OPTS
        (interests are like "LAN", "music", "gameroom", etc)

        This is intended for use to export emails to a third-party email system, like MadMimi or Mailchimp
        """
        if 'interests' not in params:
            raise HTTPRedirect('emails_by_interest?message={}', 'You must select at least one interest')

        interests = [int(i) for i in listify(params['interests'])]
        assert all(k in c.INTERESTS for k in interests)

        attendees = session.query(Attendee).filter_by(can_spam=True).order_by('email').all()

        out.writerow(["fullname", "email", "zipcode"])

        for a in attendees:
            if set(interests).intersection(a.interests_ints):
                out.writerow([a.full_name, a.email, a.zip_code])

    def emails_by_kickin(self, message=''):
        return {
            'message': message
        }

    @csv_file
    def emails_by_kickin_csv(self, out, session, **params):
        """
        Generate a list of attendee emails by what kick-in level they've donated at.
        We also select attendees with kick-in levels above the selected level.
        """
        if 'amount_extra' not in params:
            raise HTTPRedirect('emails_by_kickin?message={}', 'You must select a kick-in level')

        amount_extra = params['amount_extra']

        base_filter = Attendee.badge_status.in_([c.NEW_STATUS, c.COMPLETED_STATUS])
        email_filter = [Attendee.can_spam == True] if 'only_can_spam' in params else []  # noqa: E712
        attendee_filter = Attendee.amount_extra >= amount_extra
        if 'include_staff' in params:
            attendee_filter = or_(attendee_filter, Attendee.badge_type == c.STAFF_BADGE)

        attendees = session.query(Attendee).filter(
            base_filter, attendee_filter, *email_filter).all()

        out.writerow(["fullname", "email", "zipcode"])
        for a in attendees:
            out.writerow([a.full_name, a.email, a.zip_code])
