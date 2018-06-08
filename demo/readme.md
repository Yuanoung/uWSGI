## 初始化服务器进程

1. 设置服务器地址以及请求处理类
2. 初始化socket
3. 设置application

```
httpd = make_server('', 8782, demo_app)  # (1)

def make_server(
        host, port, app, server_class=WSGIServer, handler_class=WSGIRequestHandler
):
    """Create a new WSGI server listening on `host` and `port` for `app`"""
    # server = server_class((host, port), handler_class)  
    server = WSGIServer((host, port), WSGIRequestHandler)  # (2) 实例化服务器类
    server.set_app(app)  # 设置application．后端业务逻辑处理
    return server

class TCPServer(BaseServer):  # WSGIServer的父类
    ...
    
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        # ('', 8000), WSGIRequestHandler
        BaseServer.__init__(self, server_address, RequestHandlerClass)  # (3)设置服务器地址，端口号，以及请求处理类，每当有个请求到来时，实例话该类
        self.socket = socket.socket(self.address_family,  # 创建一个套接字
                                    self.socket_type)
        if bind_and_activate:  # (3) 绑定监听的端口，并且激活等待客户端的请求
            try:
                self.server_bind()
                self.server_activate()
            except:
                self.server_close()
                raise
```

## 客服请求
``` 
import webbrowser

webbrowser.open('http://localhost:8782/xyz?abc')
```

## 处理请求
```
httpd.handle_request()  # (1) serve one request, then exit

class BaseServer:
    ...
    def handle_request(self):
        """Handle one request, possibly blocking.
    
        Respects self.timeout.
        """
        ...
    
        # Wait until a request arrives or the timeout expires - the loop is
        # necessary to accommodate early wakeups due to EINTR.
        with _ServerSelector() as selector:
            selector.register(self, selectors.EVENT_READ)  # self是一個监听套接字
    
            while True:
                ready = selector.select(timeout)
                if ready:  # 准备好读，也就是有一个请求
                    return self._handle_request_noblock()  # (2) 不会阻塞
                else:
                    if timeout is not None:
                        timeout = deadline - time()  # 没到规定的超时时间返回，可能被中断了
                        if timeout < 0:
                            return self.handle_timeout()
    
    def _handle_request_noblock(self):
        """Handle one request, without blocking.

        I assume that selector.select() has returned that the socket is
        readable before this function was called, so there should be no risk of
        blocking in get_request().
        """
        try:
            request, client_address = self.get_request()  # (3) self.socket.accept(),接受连接，为其建立一个已连接套接字
        except OSError:
            return
        if self.verify_request(request, client_address):  # 验证地址是否相同
            try:
                self.process_request(request, client_address)  # (4) 处理请求
            except:
                self.handle_error(request, client_address)
                self.shutdown_request(request)
        else:
            self.shutdown_request(request)
    
    def process_request(self, request, client_address):
        """Call finish_request.
    
        Overridden by ForkingMixIn and ThreadingMixIn.
    
        """
        self.finish_request(request, client_address)  # (5)  request即为已连接套接字
        self.shutdown_request(request)
        
    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        # 之前设置了RequestHandlerClass＝WSGIRequestHandler，
        # 从这里可以看出为需要处理的请求初始化一个处理类实例
        self.RequestHandlerClass(request, client_address, self)  # (6)
        
```
接下来是WSGIRequestHandler的内容, 我们可以看下该WSGIRequestHandler.__mro__的继承顺序

(<class 'request.WSGIRequestHandler'>, <class 'request.BaseHTTPRequestHandler'>, 
  <class 'request.StreamRequestHandler'>, <class 'request.BaseRequestHandler'>, 
  <class 'object'>)


```
class BaseRequestHandler:
    """处理请求类的基类

    该类为每一个需要处理的请求实例化，接收三个参数：连接套接字`request`,
    客服端地址`(ip, port)`,服务器进程实例(server),然后调用handler()处理
    请求．为了定制特殊的服务，你所要做的是重载handle()方法．
    """
    def __init__(self, request, client_address, server):
        self.request = request  # 这个就是连接套接字
        self.client_address = client_address  # (ip, port)
        self.server = server  # 服务端程序
        self.setup()  # <7> StreamRequestHandler.setup() 
        try:
            self.handle()  # <8>
        finally:
            self.finish()  # <9> StreamRequestHandler.finish()
            

class StreamRequestHandler(BaseRequestHandler):
    """Define self.rfile and self.wfile for stream sockets."""

    ...

    def setup(self):  # <7>
        self.connection = self.request  # 已连接套接字
        if self.timeout is not None:
            self.connection.settimeout(self.timeout)
        if self.disable_nagle_algorithm:  # 是否使用nagle算法
            self.connection.setsockopt(socket.IPPROTO_TCP,
                                       socket.TCP_NODELAY, True)
        self.rfile = self.connection.makefile('rb', self.rbufsize)  # 读缓冲区
        self.wfile = self.connection.makefile('wb', self.wbufsize)  # 写缓冲区

    def finish(self): # <9>
        if not self.wfile.closed:
            try:
                self.wfile.flush()
            except socket.error:
                # A final socket error may have occurred here, such as
                # the local error ECONNABORTED.
                pass
        self.wfile.close()
        self.rfile.close()
        
class WSGIRequestHandler(BaseHTTPRequestHandler):

    ...
    
    def handle(self):  # <8> 执行的时这个handler(),而不是父类的handler()
        """Handle a single HTTP request"""
        from handler import ServerHandler
        self.raw_requestline = self.rfile.readline(65537)  #　从缓冲区中读取数据
        if len(self.raw_requestline) > 65536:
            self.requestline = ''
            self.request_version = ''
            self.command = ''
            self.send_error(414)
            return
    
        if not self.parse_request():  # An error code has been sent, just exit
            return
    
        # Avoid passing the raw file object wfile, which can do partial
        # writes (Issue 24291)
        stdout = BufferedWriter(self.wfile)
        try:
            handler = ServerHandler(  # 实例化真正的处理数据类
                self.rfile, stdout, self.get_stderr(), self.get_environ()
            )
            handler.request_handler = self  # backpointer for logging
            handler.run(self.server.get_app())  # demo_app　<10>
        finally:
            stdout.detach()
            
```
  
ServerHandler.__mro__


(<class '__main__.ServerHandler'>, <class '__main__.SimpleHandler'>, 
<class '__main__.BaseHandler'>, <class 'object'>)

```
class BaseHandler:

    def run(self, application):  # <10>
        """Invoke the application"""
        # Note to self: don't move the close()!  Asynchronous servers shouldn't
        # call close() from finish_response(), so if you close() anywhere but
        # the double-error branch here, you'll break asynchronous servers by
        # prematurely closing.  Async servers must return from 'run()' without
        # closing if there might still be output to iterate over.
        try:
            self.setup_environ()  # 设置wsgi的环境变量
            self.result = application(self.environ, self.start_response)  # <11> 调用自定义的demo
            self.finish_response()  # <12> 响应：头部，以及内容
        except:
            try:
                self.handle_error()
            except:
                # If we get an error handling an error, just give up already!
                self.close()
                raise  # ...and let the actual server figure it out.
                
# application
def demo_app(environ, start_response):  # <11>
    from io import StringIO
    # 设置这个缓冲区，个人猜测的理由如下：
    # s += string_val，这个效率很差．我们知道python中str对象时不可变的，会不断的分配内存以及销毁内存
    #    tmp = s + string_val
    #    s = temp
    stdout = StringIO()
    print("Hello world!", file=stdout)  # 把数据写入到StringIO()缓冲区，stdout.getvalue()取出数据
    print(file=stdout)
    h = sorted(environ.items())
    for k, v in h:
        print(k, '=', repr(v), file=stdout)
    start_response("200 OK", [('Content-Type', 'text/plain; charset=utf-8')])  #　如果有错误则处理错误，否则设置响应头部
    return [stdout.getvalue().encode("utf-8")]  # 这个一定是一个列表．从缓冲区中取出数据，并且以utf-8格式编码，将其变为bytes格式
    
  
class BaseHandler:

    ... 
    
    def finish_response(self):  # <12>
        """Send any iterable data, then close self and the iterable

        Subclasses intended for use in asynchronous servers will
        want to redefine this method, such that it sets up callbacks
        in the event loop to iterate over the data, and to call
        'self.close()' once the response is finished.
        """
        try:
            if not self.result_is_file() or not self.sendfile():
                for data in self.result:
                    self.write(data)  # <13> 开始往套接字的写缓冲区写入数据
                self.finish_content()
        finally:
            self.close()
            
    def write(self, data):
        """'write()' callable as specified by PEP 3333"""

        assert type(data) is bytes, \
            "write() argument must be a bytes instance"

        if not self.status:
            raise AssertionError("write() before start_response()")

        elif not self.headers_sent:  # 如果该响应头部还没有发送
            # Before the first output, send the stored headers
            self.bytes_sent = len(data)  # make sure we know content-length
            self.send_headers()
        else:
            self.bytes_sent += len(data)

        # XXX check Content-Length and truncate if too many bytes written?
        self._write(data)
        self._flush()
        
class SimpleHandler(BaseHandler):
    
    ... 
    
    def _write(self, data):
        result = self.stdout.write(data) 
        if result is None or result == len(data):
            return
        from warnings import warn
        warn("SimpleHandler.stdout.write() should not do partial writes",
             DeprecationWarning)
        while True:  # 返回的值过大，需要分多次发送
            data = data[result:]
            if not data:
                break
            result = self.stdout.write(data)

    def _flush(self):
        self.stdout.flush()  # 冲刷缓冲区
        self._flush = self.stdout.flush
````