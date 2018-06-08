from server import WSGIServer
from request import WSGIRequestHandler


def demo_app(environ, start_response):
    from io import StringIO
    stdout = StringIO()
    print("Hello world!", file=stdout)  # 把数据写入到StringIO()缓冲区，stdout.getvalue()取出数据
    print(file=stdout)
    h = sorted(environ.items())
    for k, v in h:
        print(k, '=', repr(v), file=stdout)
    start_response("200 OK", [('Content-Type', 'text/plain; charset=utf-8')])
    return [stdout.getvalue().encode("utf-8")]


def make_server(
        host, port, app, server_class=WSGIServer, handler_class=WSGIRequestHandler
):
    """Create a new WSGI server listening on `host` and `port` for `app`"""
    # server = server_class((host, port), handler_class)
    server = WSGIServer((host, port), WSGIRequestHandler)  # 实例化服务器类
    server.set_app(app)
    return server


if __name__ == '__main__':
    httpd = make_server('', 8782, demo_app)
    sa = httpd.socket.getsockname()
    print("Serving HTTP on", sa[0], "port", sa[1], "...")
    import webbrowser

    webbrowser.open('http://localhost:8782/xyz?abc')
    httpd.handle_request()  # serve one request, then exit
    httpd.server_close()
