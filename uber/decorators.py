from uber.common import *

def check_if_can_reg(func):
    @wraps(func)
    def with_check(*args,**kwargs):
        if state.BADGES_SOLD >= MAX_BADGE_SALES:
            return render('static_views/prereg_soldout.html')
        elif state.PREREG_OPEN == "notopenyet":
            return render('static_views/prereg_not_yet_open.html')
        elif state.PREREG_OPEN == "closed":
            return render('static_views/prereg_closed.html')
        else:
            return func(*args,**kwargs)
    return with_check

def site_mappable(func):
    func.site_mappable = True
    return func


def cached_property(func):
    pname = '_' + func.__name__
    @property
    @wraps(func)
    def caching(self, *args, **kwargs):
        if not hasattr(self, pname):
            setattr(self, pname, func(self, *args, **kwargs))
        return getattr(self, pname)
    return caching


def show_queries(func):
    @wraps(func)
    def queries(self, *args, **kwargs):
        connection.queries[:] = []
        stripped = [arg for arg in args if arg != 'querylog']
        try:
            return func(self, *stripped, **kwargs)
        finally:
            if 'querylog' in args:
                cherrypy.response.headers['Content-type'] = 'text/plain'
                return pformat(connection.queries)
    return queries


def csrf_protected(func):
    @wraps(func)
    def protected(*args, csrf_token, **kwargs):
        check_csrf(csrf_token)
        return func(*args, **kwargs)
    return protected


# requires: POST and a valid CSRF token
def ajax(func):
    @wraps(func)
    def returns_json(*args, **kwargs):
        cherrypy.response.headers['Content-Type'] = 'application/json'
        assert cherrypy.request.method == 'POST', 'POST required'
        check_csrf(kwargs.pop('csrf_token', None))
        return json.dumps(func(*args, **kwargs)).encode('utf-8')
    return returns_json

# used for things that should be publicly called, i.e. APIs and such.
# supports GET or POST
def ajax_public_callable(func):
    @wraps(func)
    def returns_json(*args, **kwargs):
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(func(*args, **kwargs)).encode('utf-8')
    return returns_json


def multifile_zipfile(func):
    @wraps(func)
    def zipfile_out(self, session):
        zipfile_writer = BytesIO()
        with zipfile.ZipFile(zipfile_writer, mode='w') as zip_file:
            func(self, zip_file, session)

        # must do this after creating the zip file as other decorators may have changed this
        # for example, if a .zip file is created from several .csv files, they may each set content-type.
        cherrypy.response.headers['Content-Type'] = 'application/zip'
        cherrypy.response.headers['Content-Disposition'] = 'attachment; filename=' + func.__name__ + '.zip'

        return zipfile_writer.getvalue()
    return zipfile_out


def _set_csv_base_filename(base_filename):
    """
    Set the correct headers when outputting CSV files to specify the filename the browser should use
    """
    cherrypy.response.headers['Content-Disposition'] = 'attachment; filename=' + base_filename + '.csv'


def csv_file(func):
    @wraps(func)
    def csvout(self):
        writer = StringIO()
        func(self, csv.writer(writer))
        output = writer.getvalue().encode('utf-8')
        # set headers last in case there were errors, so end user still see error page
        cherrypy.response.headers['Content-Type'] = 'application/csv'
        _set_csv_base_filename(func.__name__)
        return output
    return csvout


def set_csv_filename(func):
    """
    Use this to override CSV filenames, useful when working with aliases and redirects to make it print the correct name
    """
    @wraps(func)
    def change_filename(self, override_filename=None, *args, **kwargs):
        out = func(self, *args, **kwargs)
        _set_csv_base_filename(override_filename or func.__name__)
        return out
    return change_filename


def get_module_name(class_or_func):
    return class_or_func.__module__.split('.')[-1]



def credit_card(func):
    @wraps(func)
    def charge(self, payment_id, stripeToken, **ignored):
        if ignored:
            log.error('received unexpected stripe parameters: {}', ignored)
        try:
            return func(self, payment_id=payment_id, stripeToken=stripeToken)
        except HTTPRedirect:
            raise
        except:
            send_email(ADMIN_EMAIL, [ADMIN_EMAIL, 'dom@magfest.org'], 'MAGFest Stripe error',
                       'Got an error while calling charge(self, payment_id={!r}, stripeToken={!r}, ignored={}):\n{}'
                       .format(payment_id, stripeToken, ignored, traceback.format_exc()))
            return traceback.format_exc()
    return charge


def renderable_data(data = None):
    data = data or {}
    data.update({m.__name__: m for m in all_models()})
    data.update({k: v for k,v in constants.__dict__.items() if re.match('^[_A-Z0-9]*$', k)})
    data.update({k: getattr(state, k) for k in dir(state) if re.match('^[_A-Z0-9]*$', k)})
    data.update({
        'now':   datetime.now(),
        'PAGE':  cherrypy.request.path_info.split('/')[-1]
    })
    try:
        data['CSRF_TOKEN'] = cherrypy.session['csrf_token']
    except:
        pass
    
    access = AdminAccount.access_set()
    for acctype in ['ACCOUNTS','PEOPLE','STUFF','MONEY','CHALLENGES','CHECKINS']:
        data['HAS_' + acctype + '_ACCESS'] = getattr(constants, acctype) in access
    
    return data

# render using the first template that actually exists in template_name_list
def render(template_name_list, data = None):
    data = renderable_data(data)
    template = loader.select_template(listify(template_name_list))
    rendered = template.render( Context(data) )

    rendered = screw_you_nick(rendered, template) # lolz.

    return rendered.encode('utf-8')


# this is a Magfest inside joke.
# Nick gets mad when people call Magfest a 'convention'. He always says 'It's not a convention, it's a festival'
# So........ if Nick is logged in.... let's annoy him a bit :)
def screw_you_nick(rendered, template):
    if not AT_THE_CON and AdminAccount.is_nick() and 'emails' not in template and 'history' not in template and 'form' not in rendered:
        return rendered.replace('festival', 'convention').replace('Fest', 'Con') # lolz.
    else:
        return rendered

# TODO: sanitize for XSS attacks; currently someone can only attack themselves, but still...
def ng_render(fname, **kwargs):
    class AngularTemplate(string.Template):
        delimiter = '%__'
    
    with open(os.path.join(MODULE_ROOT, 'templates', fname)) as f:
        data = {k: (str(v).lower() if v in [True, False] else v) for k, v in renderable_data(kwargs).items()}
        return AngularTemplate(f.read()).substitute(**data)


def _get_module_name(class_or_func):
    return class_or_func.__module__.split('.')[-1]

def _get_template_filename(func):
    return os.path.join(_get_module_name(func), func.__name__ + '.html')

def ng_renderable(func):
    @wraps(func)
    def with_rendering(*args, **kwargs):
        result = func(*args, **kwargs)
        return result if isinstance(result, str) else ng_render(_get_template_filename(func), **result)
    
    spec = inspect.getfullargspec(func)
    if spec.args == ['self'] and not spec.varargs and not spec.varkw:
        return site_mappable(with_rendering)
    else:
        return with_rendering

def renderable(func):
    @wraps(func)
    def with_rendering(*args, **kwargs):
        result = func(*args, **kwargs)
        if isinstance(result, dict):
            return render(_get_template_filename(func), result)
        else:
            return result
    return with_rendering

def unrestricted(func):
    func.restricted = False
    return func

def restricted(func):
    @wraps(func)
    def with_restrictions(*args, **kwargs):
        if func.restricted:
            if func.restricted == (SIGNUPS,):
                if not cherrypy.session.get('staffer_id'):
                    raise HTTPRedirect('../signups/login?message=You+are+not+logged+in')
            
            elif cherrypy.session.get('account_id') is None:
                raise HTTPRedirect('../accounts/login?message=You+are+not+logged+in')
            
            else:
                if not set(func.restricted).intersection(AdminAccount.access_set()):
                    if len(func.restricted) == 1:
                        return 'You need {} access for this page'.format(dict(ACCESS_OPTS)[func.restricted[0]])
                    else:
                        return ('You need at least one of the following access levels to view this page: '
                            + ', '.join(dict(ACCESS_OPTS)[r] for r in func.restricted))
        
        return func(*args, **kwargs)
    return with_restrictions


def set_renderable(func, acccess):
    """
    Return a function that is flagged correctly and is ready to be called by cherrypy as a request
    """
    func.restricted = getattr(func, 'restricted', acccess)
    new_func = show_queries(restricted(renderable(func)))
    new_func.exposed = True
    new_func._orig = func

    return new_func


class all_renderable:
    def __init__(self, *needs_access, angular=False):
        self.angular = angular
        self.needs_access = needs_access
    
    def __call__(self, klass):
        if self.angular:
            def ng(self, template):
                return ng_render(os.path.join(_get_module_name(klass), 'angular', template))
            klass.ng = ng
        
        for name,func in klass.__dict__.items():
            if hasattr(func, '__call__'):
                new_func = set_renderable(func, self.needs_access)
                setattr(klass, name, new_func)
        return klass


register = template.Library()
def tag(klass):
    @register.tag(klass.__name__)
    def tagged(parser, token):
        return klass(*token.split_contents()[1:])
    return klass


def create_redirect(url, access=[c.PEOPLE]):
    """
    Return a function which redirects to the given url when called.
    """
    def redirect(self):
        raise HTTPRedirect(url)
    renderable_func = set_renderable(redirect, access)
    return renderable_func


class alias_to_site_section(object):
    """
    Inject a URL redirect from another page to the decorated function.
    This is useful for downstream plugins to add or change functions in upstream plugins to modify their behavior.

    Example: if you move the explode_kittens() function from the core's site_section/summary.py page to a plugin,
    in that plugin you can create an alias back to the original function like this:

    @alias_to_site_section('summary')
    def explode_kittens(...):
        ...

    Please note that this doesn't preserve arguments, it just causes a redirect.  It's most useful for pages without
    arguments like reports and landing pages.
    """
    def __init__(self, site_section_name, alias_name=None, url=None):
        self.site_section_name = site_section_name
        self.alias_name = alias_name
        self.url = url

    def __call__(self, func):
        root = getattr(uber.site_sections, self.site_section_name).Root
        redirect_func = create_redirect(self.url or '../' + get_module_name(func) + '/' + func.__name__)
        setattr(root, self.alias_name or func.__name__, redirect_func)
        return func
