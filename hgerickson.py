"""
Mercurial plugin for posting review to Erickson code review
tool (github.com/echlebek/erickson)

"""
from mercurial import cmdutil, hg, ui, mdiff, patch, util
from mercurial.i18n import _


class HTTPSRequests(object):

    def __init__(self, opener, cookies, server, csrf):
        self.opener = opener
        self.cookies = cookies
        self.server = server
        self.csrf = csrf

    def post(self, path, data):
        from urllib import urlencode
        from urllib2 import Request
        from urlparse import urljoin

        headers = {"X-CSRF-Token": self.csrf}
        url = urljoin(self.server, path)
        req = Request(url, data=urlencode(data), headers=headers)
        response = self.opener.open(req)

        return response.getcode()


def https_requests(server, insecure):
    from urllib2 import HTTPSHandler, HTTPCookieProcessor, Request, build_opener
    import cookielib
    import ssl

    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    cookies = cookielib.LWPCookieJar()
    opener = build_opener(
        HTTPSHandler(context=context),
        HTTPCookieProcessor(cookies)
    )

    # Get CSRF
    req = Request(server)
    req.get_method = lambda: "HEAD"

    response = opener.open(req)
    csrf = response.info().getheader("X-CSRF-Token")

    return HTTPSRequests(opener, cookies, server, csrf)


def review(ui, repo, rev='.', **opts):
    from urllib2 import HTTPError
    from getpass import getpass

    server = _find_server(ui, opts)

    ctx = repo['.']
    parent = opts.get("parent") or ctx.parents()[0]

    username = opts.get("username") or ui.config("hgerickson", "username")
    if not username:
        raise _abort("please specify Erickson account username in your .hgrc file "
                     "or using the --username flag")

    rr = https_requests(server, insecure=opts.get("insecure"))

    try:
        rr.post("/login", {
            "username": username,
            "password": getpass("Password for {}: ".format(username))
        })
    except HTTPError, e:
        raise _abort("could not login to the server due to network error: {}".format(e))

    try:
        rr.post("/reviews", {
            "diff": _get_diff(ui, repo, ctx, repo[parent]),
            "commitmsg": _get_summary(repo, ctx, repo[parent]),
            "repository": ui.config("paths", "default"),
            "submitter": username,
        })
    except HTTPError, e:
        raise _abort("could not submit the review due network error: {}".format(e))


def _find_server(ui, opts):
    server = opts.get("server") or ui.config("hgerickson", "server")
    if not server:
        raise _abort("please specify a reviewboard server in your .hgrc file "
                     "or using the --server flag")

    return server


def _get_diff(ui, repo, ctx, parent_ctx):
    """Return diff for the specified revision."""
    return "".join(patch.diff(repo, parent_ctx.node(), ctx.node()))


def _get_summary(repo, ctx, parent_ctx):
    """Build a summary from all changesets included in this review."""
    contexts = []
    for node in repo.changelog.nodesbetween([parent_ctx.node()], [ctx.node()])[0]:
        if node != parent_ctx.node():
            contexts.append(repo[node])

    if len(contexts) == 0:
        contexts.append(ctx)

    return "* * *\n\n".join(map(_format_summary, contexts[::-1]))


def _format_summary(ctx):
    return "\n".join([
        "Changeset {}:{}".format(ctx.rev(), ctx),
        "---------------------------",
        "{}\n".format(ctx.description())
    ])


def _abort(message):
    return util.Abort(_(unicode(message)))


cmdtable = {
    "review": (review,
               [("e", "existing", "", _("existing request ID to update")),
                ("p", "parent", "", _("parent revision for the uploaded diff")),
                ("s", "server", "", _("Erickson server URL")),
                ("", "username", "", _("username for the Erickson account")),
                ("k", "insecure", False, _("don't verify SSL certificates"))],
               "hg review [--parent REV]")
}
