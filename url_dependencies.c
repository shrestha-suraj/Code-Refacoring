static CURLcode parseurlandfillconn(struct SessionHandle *data,
                                    struct connectdata *conn,
                                    bool *prot_missing)
{
  char *at;
  char *fragment;
  char *path = data->state.path;
  char *query;
  int rc;
  char protobuf[16];
  const char *protop;

  *prot_missing = FALSE;

  /*************************************************************
   * Parse the URL.
   *
   * We need to parse the url even when using the proxy, because we will need
   * the hostname and port in case we are trying to SSL connect through the
   * proxy -- and we don't know if we will need to use SSL until we parse the
   * url ...
   ************************************************************/
  if((2 == sscanf(data->change.url, "%15[^:]:%[^\n]",
                  protobuf, path)) &&
     Curl_raw_equal(protobuf, "file")) {
    if(path[0] == '/' && path[1] == '/') {
      /* Allow omitted hostname (e.g. file:/<path>).  This is not strictly
       * speaking a valid file: URL by RFC 1738, but treating file:/<path> as
       * file://localhost/<path> is similar to how other schemes treat missing
       * hostnames.  See RFC 1808. */

      /* This cannot be done with strcpy() in a portable manner, since the
         memory areas overlap! */
      memmove(path, path + 2, strlen(path + 2)+1);
    }
    /*
     * we deal with file://<host>/<path> differently since it supports no
     * hostname other than "localhost" and "127.0.0.1", which is unique among
     * the URL protocols specified in RFC 1738
     */
    if(path[0] != '/') {
      /* the URL included a host name, we ignore host names in file:// URLs
         as the standards don't define what to do with them */
      char *ptr=strchr(path, '/');
      if(ptr) {
        /* there was a slash present

           RFC1738 (section 3.1, page 5) says:

           The rest of the locator consists of data specific to the scheme,
           and is known as the "url-path". It supplies the details of how the
           specified resource can be accessed. Note that the "/" between the
           host (or port) and the url-path is NOT part of the url-path.

           As most agents use file://localhost/foo to get '/foo' although the
           slash preceding foo is a separator and not a slash for the path,
           a URL as file://localhost//foo must be valid as well, to refer to
           the same file with an absolute path.
        */

        if(ptr[1] && ('/' == ptr[1]))
          /* if there was two slashes, we skip the first one as that is then
             used truly as a separator */
          ptr++;

        /* This cannot be made with strcpy, as the memory chunks overlap! */
        memmove(path, ptr, strlen(ptr)+1);
      }
    }

    protop = "file"; /* protocol string */
  }
  else {
    /* clear path */
    path[0]=0;

    if(2 > sscanf(data->change.url,
                   "%15[^\n:]://%[^\n/?]%[^\n]",
                   protobuf,
                   conn->host.name, path)) {

      /*
       * The URL was badly formatted, let's try the browser-style _without_
       * protocol specified like 'http://'.
       */
      rc = sscanf(data->change.url, "%[^\n/?]%[^\n]", conn->host.name, path);
      if(1 > rc) {
        /*
         * We couldn't even get this format.
         * djgpp 2.04 has a sscanf() bug where 'conn->host.name' is
         * assigned, but the return value is EOF!
         */
#if defined(__DJGPP__) && (DJGPP_MINOR == 4)
        if (!(rc == -1 && *conn->host.name))
#endif
        {
          failf(data, "<url> malformed");
          return CURLE_URL_MALFORMAT;
        }
      }

      /*
       * Since there was no protocol part specified, we guess what protocol it
       * is based on the first letters of the server name.
       */

      /* Note: if you add a new protocol, please update the list in
       * lib/version.c too! */

      if(checkprefix("FTP.", conn->host.name))
        protop = "ftp";
      else if(checkprefix("DICT.", conn->host.name))
        protop = "DICT";
      else if(checkprefix("LDAP.", conn->host.name))
        protop = "LDAP";
      else if(checkprefix("IMAP.", conn->host.name))
        protop = "IMAP";
      else {
        protop = "http";
      }

      *prot_missing = TRUE; /* not given in URL */
    }
    else
      protop = protobuf;
  }

  /* We search for '?' in the host name (but only on the right side of a
   * @-letter to allow ?-letters in username and password) to handle things
   * like http://example.com?param= (notice the missing '/').
   */
  at = strchr(conn->host.name, '@');
  if(at)
    query = strchr(at+1, '?');
  else
    query = strchr(conn->host.name, '?');

  if(query) {
    /* We must insert a slash before the '?'-letter in the URL. If the URL had
       a slash after the '?', that is where the path currently begins and the
       '?string' is still part of the host name.

       We must move the trailing part from the host name and put it first in
       the path. And have it all prefixed with a slash.
    */

    size_t hostlen = strlen(query);
    size_t pathlen = strlen(path);

    /* move the existing path plus the zero byte forward, to make room for
       the host-name part */
    memmove(path+hostlen+1, path, pathlen+1);

     /* now copy the trailing host part in front of the existing path */
    memcpy(path+1, query, hostlen);

    path[0]='/'; /* prepend the missing slash */

    *query=0; /* now cut off the hostname at the ? */
  }
  else if(!path[0]) {
    /* if there's no path set, use a single slash */
    strcpy(path, "/");
  }

  /* If the URL is malformatted (missing a '/' after hostname before path) we
   * insert a slash here. The only letter except '/' we accept to start a path
   * is '?'.
   */
  if(path[0] == '?') {
    /* We need this function to deal with overlapping memory areas. We know
       that the memory area 'path' points to is 'urllen' bytes big and that
       is bigger than the path. Use +1 to move the zero byte too. */
    memmove(&path[1], path, strlen(path)+1);
    path[0] = '/';
  }

  if (conn->host.name[0] == '[') {
    /* This looks like an IPv6 address literal.  See if there is an address
       scope.  */
    char *percent = strstr (conn->host.name, "%25");
    if (percent) {
      char *endp;
      unsigned long scope = strtoul (percent + 3, &endp, 10);
      if (*endp == ']') {
        /* The address scope was well formed.  Knock it out of the
           hostname. */
        memmove(percent, endp, strlen(endp)+1);
        if (!data->state.this_is_a_follow)
          /* Don't honour a scope given in a Location: header */
          conn->scope = (unsigned int)scope;
      } else
        infof(data, "Invalid IPv6 address format\n");
    }
  }

  if(data->set.scope)
    /* Override any scope that was set above.  */
    conn->scope = data->set.scope;

  /* Remove the fragment part of the path. Per RFC 2396, this is always the
     last part of the URI. We are looking for the first '#' so that we deal
     gracefully with non conformant URI such as http://example.com#foo#bar. */
  fragment = strchr(path, '#');
  if(fragment)
    *fragment = 0;

  /*
   * So if the URL was A://B/C#D,
   *   protop is A
   *   conn->host.name is B
   *   data->state.path is /C
   */

  return findprotocol(data, conn, protop);
}


static CURLcode create_conn(struct SessionHandle *data,
                            struct connectdata **in_connect,
                            bool *async)
{
  CURLcode result=CURLE_OK;
  struct connectdata *conn;
  struct connectdata *conn_temp = NULL;
  size_t urllen;
  char user[MAX_CURL_USER_LENGTH];
  char passwd[MAX_CURL_PASSWORD_LENGTH];
  bool reuse;
  char *proxy = NULL;
  bool prot_missing = FALSE;

  *async = FALSE;

  /*************************************************************
   * Check input data
   *************************************************************/

  if(!data->change.url)
    return CURLE_URL_MALFORMAT;

  /* First, split up the current URL in parts so that we can use the
     parts for checking against the already present connections. In order
     to not have to modify everything at once, we allocate a temporary
     connection data struct and fill in for comparison purposes. */
  conn = allocate_conn(data);

  if(!conn)
    return CURLE_OUT_OF_MEMORY;

  /* We must set the return variable as soon as possible, so that our
     parent can cleanup any possible allocs we may have done before
     any failure */
  *in_connect = conn;

  /* This initing continues below, see the comment "Continue connectdata
   * initialization here" */

  /***********************************************************
   * We need to allocate memory to store the path in. We get the size of the
   * full URL to be sure, and we need to make it at least 256 bytes since
   * other parts of the code will rely on this fact
   ***********************************************************/
#define LEAST_PATH_ALLOC 256
  urllen=strlen(data->change.url);
  if(urllen < LEAST_PATH_ALLOC)
    urllen=LEAST_PATH_ALLOC;

  /*
   * We malloc() the buffers below urllen+2 to make room for to possibilities:
   * 1 - an extra terminating zero
   * 2 - an extra slash (in case a syntax like "www.host.com?moo" is used)
   */

  Curl_safefree(data->state.pathbuffer);
  data->state.pathbuffer = malloc(urllen+2);
  if(NULL == data->state.pathbuffer)
    return CURLE_OUT_OF_MEMORY; /* really bad error */
  data->state.path = data->state.pathbuffer;

  conn->host.rawalloc = malloc(urllen+2);
  if(NULL == conn->host.rawalloc)
    return CURLE_OUT_OF_MEMORY;

  conn->host.name = conn->host.rawalloc;
  conn->host.name[0] = 0;

  result = parseurlandfillconn(data, conn, &prot_missing);
  if(result != CURLE_OK) {
      return result;
  }

  /*************************************************************
   * No protocol part in URL was used, add it!
   *************************************************************/
  if(prot_missing) {
    /* We're guessing prefixes here and if we're told to use a proxy or if
       we're gonna follow a Location: later or... then we need the protocol
       part added so that we have a valid URL. */
    char *reurl;

    reurl = aprintf("%s://%s", conn->handler->scheme, data->change.url);

    if(!reurl) {
      Curl_safefree(proxy);
      return CURLE_OUT_OF_MEMORY;
    }

    data->change.url = reurl;
    data->change.url_alloc = TRUE; /* free this later */
  }

  /*************************************************************
   * Parse a user name and password in the URL and strip it out
   * of the host name
   *************************************************************/
  result = parse_url_userpass(data, conn, user, passwd);
  if(result != CURLE_OK)
    return result;

#ifndef CURL_DISABLE_PROXY
  /*************************************************************
   * Extract the user and password from the authentication string
   *************************************************************/
  if(conn->bits.proxy_user_passwd) {
    result = parse_proxy_auth(data, conn);
    if(result != CURLE_OK)
        return result;
  }

  /*************************************************************
   * Detect what (if any) proxy to use
   *************************************************************/
  if(data->set.str[STRING_PROXY]) {
    proxy = strdup(data->set.str[STRING_PROXY]);
    /* if global proxy is set, this is it */
    if(NULL == proxy) {
      failf(data, "memory shortage");
      return CURLE_OUT_OF_MEMORY;
    }
  }

  if(data->set.str[STRING_NOPROXY] &&
     check_noproxy(conn->host.name, data->set.str[STRING_NOPROXY])) {
    if(proxy) {
      free(proxy);  /* proxy is in exception list */
      proxy = NULL;
    }
  }
  else if(!proxy)
    proxy = detect_proxy(conn);

  if(proxy && !*proxy) {
    free(proxy);  /* Don't bother with an empty proxy string */
    proxy = NULL;
  }
  /* proxy must be freed later unless NULL */
  if(proxy && !(conn->handler->flags & PROTOPT_BANPROXY)) {
    if((conn->proxytype == CURLPROXY_HTTP) ||
       (conn->proxytype == CURLPROXY_HTTP_1_0)) {
#ifdef CURL_DISABLE_HTTP
      /* asking for a HTTP proxy is a bit funny when HTTP is disabled... */
      return CURLE_UNSUPPORTED_PROTOCOL;
#else
      /* force this connection's protocol to become HTTP */
      conn->handler = &Curl_handler_http;
      conn->bits.httpproxy = TRUE;
#endif
    }
    conn->bits.proxy = TRUE;
  }
  else {
    /* we aren't using the proxy after all... */
    conn->bits.proxy = FALSE;
    conn->bits.httpproxy = FALSE;
    conn->bits.proxy_user_passwd = FALSE;
    conn->bits.tunnel_proxy = FALSE;
  }

  /***********************************************************************
   * If this is supposed to use a proxy, we need to figure out the proxy
   * host name, so that we can re-use an existing connection
   * that may exist registered to the same proxy host.
   ***********************************************************************/
  if(proxy) {
    result = parse_proxy(data, conn, proxy);
    /* parse_proxy has freed the proxy string, so don't try to use it again */
    proxy = NULL;
    if(result != CURLE_OK)
      return result;
  }
#endif /* CURL_DISABLE_PROXY */

  /*************************************************************
   * Setup internals depending on protocol. Needs to be done after
   * we figured out what/if proxy to use.
   *************************************************************/
  result = setup_connection_internals(conn);
  if(result != CURLE_OK) {
    Curl_safefree(proxy);
    return result;
  }

  conn->recv[FIRSTSOCKET] = Curl_recv_plain;
  conn->send[FIRSTSOCKET] = Curl_send_plain;
  conn->recv[SECONDARYSOCKET] = Curl_recv_plain;
  conn->send[SECONDARYSOCKET] = Curl_send_plain;

  /***********************************************************************
   * file: is a special case in that it doesn't need a network connection
   ***********************************************************************/
#ifndef CURL_DISABLE_FILE
  if(conn->handler->protocol & CURLPROTO_FILE) {
    bool done;
    /* this is supposed to be the connect function so we better at least check
       that the file is present here! */
    DEBUGASSERT(conn->handler->connect_it);
    result = conn->handler->connect_it(conn, &done);

    /* Setup a "faked" transfer that'll do nothing */
    if(CURLE_OK == result) {
      conn->data = data;
      conn->bits.tcpconnect = TRUE; /* we are "connected */

      ConnectionStore(data, conn);

      /*
       * Setup whatever necessary for a resumed transfer
       */
      result = setup_range(data);
      if(result) {
        DEBUGASSERT(conn->handler->done);
        /* we ignore the return code for the protocol-specific DONE */
        (void)conn->handler->done(conn, result, FALSE);
        return result;
      }

      Curl_setup_transfer(conn, -1, -1, FALSE, NULL, /* no download */
                          -1, NULL); /* no upload */
    }

    return result;
  }
#endif

  /*************************************************************
   * If the protocol is using SSL and HTTP proxy is used, we set
   * the tunnel_proxy bit.
   *************************************************************/
  if((conn->given->flags&PROTOPT_SSL) && conn->bits.httpproxy)
    conn->bits.tunnel_proxy = TRUE;

  /*************************************************************
   * Figure out the remote port number and fix it in the URL
   *************************************************************/
  result = parse_remote_port(data, conn);
  if(result != CURLE_OK)
    return result;

  /*************************************************************
   * Check for an overridden user name and password, then set it
   * for use
   *************************************************************/
  override_userpass(data, conn, user, passwd);
  result = set_userpass(conn, user, passwd);
  if(result != CURLE_OK)
    return result;

  /* Get a cloned copy of the SSL config situation stored in the
     connection struct. But to get this going nicely, we must first make
     sure that the strings in the master copy are pointing to the correct
     strings in the session handle strings array!

     Keep in mind that the pointers in the master copy are pointing to strings
     that will be freed as part of the SessionHandle struct, but all cloned
     copies will be separately allocated.
  */
  data->set.ssl.CApath = data->set.str[STRING_SSL_CAPATH];
  data->set.ssl.CAfile = data->set.str[STRING_SSL_CAFILE];
  data->set.ssl.CRLfile = data->set.str[STRING_SSL_CRLFILE];
  data->set.ssl.issuercert = data->set.str[STRING_SSL_ISSUERCERT];
  data->set.ssl.random_file = data->set.str[STRING_SSL_RANDOM_FILE];
  data->set.ssl.egdsocket = data->set.str[STRING_SSL_EGDSOCKET];
  data->set.ssl.cipher_list = data->set.str[STRING_SSL_CIPHER_LIST];
#ifdef USE_TLS_SRP
  data->set.ssl.username = data->set.str[STRING_TLSAUTH_USERNAME];
  data->set.ssl.password = data->set.str[STRING_TLSAUTH_PASSWORD];
#endif

  if(!Curl_clone_ssl_config(&data->set.ssl, &conn->ssl_config))
    return CURLE_OUT_OF_MEMORY;

  /*************************************************************
   * Check the current list of connections to see if we can
   * re-use an already existing one or if we have to create a
   * new one.
   *************************************************************/

  /* reuse_fresh is TRUE if we are told to use a new connection by force, but
     we only acknowledge this option if this is not a re-used connection
     already (which happens due to follow-location or during a HTTP
     authentication phase). */
  if(data->set.reuse_fresh && !data->state.this_is_a_follow)
    reuse = FALSE;
  else
    reuse = ConnectionExists(data, conn, &conn_temp);

  if(reuse) {
    /*
     * We already have a connection for this, we got the former connection
     * in the conn_temp variable and thus we need to cleanup the one we
     * just allocated before we can move along and use the previously
     * existing one.
     */
    reuse_conn(conn, conn_temp);
    free(conn);          /* we don't need this anymore */
    conn = conn_temp;
    *in_connect = conn;
    infof(data, "Re-using existing connection! (#%ld) with host %s\n",
          conn->connectindex,
          conn->proxy.name?conn->proxy.dispname:conn->host.dispname);
  }
  else {
    /*
     * This is a brand new connection, so let's store it in the connection
     * cache of ours!
     */
    ConnectionStore(data, conn);
  }

  /*
   * Setup whatever necessary for a resumed transfer
   */
  result = setup_range(data);
  if(result)
    return result;

  /* Continue connectdata initialization here. */

  /*
   * Inherit the proper values from the urldata struct AFTER we have arranged
   * the persistent connection stuff
   */
  conn->fread_func = data->set.fread_func;
  conn->fread_in = data->set.in;
  conn->seek_func = data->set.seek_func;
  conn->seek_client = data->set.seek_client;

  /*************************************************************
   * Resolve the address of the server or proxy
   *************************************************************/
  result = resolve_server(data, conn, async);

  return result;
}


//Declared but not called with in the function
static CURLcode parse_remote_port(struct SessionHandle *data,
                                  struct connectdata *conn)
{
  char *portptr;
  char endbracket;

  /* Note that at this point, the IPv6 address cannot contain any scope
     suffix as that has already been removed in the parseurlandfillconn()
     function */
  if((1 == sscanf(conn->host.name, "[%*45[0123456789abcdefABCDEF:.]%c",
                  &endbracket)) &&
     (']' == endbracket)) {
    /* this is a RFC2732-style specified IP-address */
    conn->bits.ipv6_ip = TRUE;

    conn->host.name++; /* skip over the starting bracket */
    portptr = strchr(conn->host.name, ']');
    if(portptr) {
      *portptr++ = '\0'; /* zero terminate, killing the bracket */
      if(':' != *portptr)
        portptr = NULL; /* no port number available */
    }
  }
  else
    portptr = strrchr(conn->host.name, ':');

  if(data->set.use_port && data->state.allow_port) {
    /* if set, we use this and ignore the port possibly given in the URL */
    conn->remote_port = (unsigned short)data->set.use_port;
    if(portptr)
      *portptr = '\0'; /* cut off the name there anyway - if there was a port
                      number - since the port number is to be ignored! */
    if(conn->bits.httpproxy) {
      /* we need to create new URL with the new port number */
      char *url;
      char type[12]="";

      if(conn->bits.type_set)
        snprintf(type, sizeof(type), ";type=%c",
                 data->set.prefer_ascii?'A':
                 (data->set.ftp_list_only?'D':'I'));

      /*
       * This synthesized URL isn't always right--suffixes like ;type=A are
       * stripped off. It would be better to work directly from the original
       * URL and simply replace the port part of it.
       */
      url = aprintf("%s://%s%s%s:%hu%s%s%s", conn->given->scheme,
                    conn->bits.ipv6_ip?"[":"", conn->host.name,
                    conn->bits.ipv6_ip?"]":"", conn->remote_port,
                    data->state.slash_removed?"/":"", data->state.path,
                    type);
      if(!url)
        return CURLE_OUT_OF_MEMORY;

      if(data->change.url_alloc)
        free(data->change.url);

      data->change.url = url;
      data->change.url_alloc = TRUE;
    }
  }
  else if(portptr) {
    /* no CURLOPT_PORT given, extract the one from the URL */

    char *rest;
    unsigned long port;

    port=strtoul(portptr+1, &rest, 10);  /* Port number must be decimal */

    if(rest != (portptr+1) && *rest == '\0') {
      /* The colon really did have only digits after it,
       * so it is either a port number or a mistake */

      if(port > 0xffff) {   /* Single unix standard says port numbers are
                              * 16 bits long */
        failf(data, "Port number too large: %lu", port);
        return CURLE_URL_MALFORMAT;
      }

      *portptr = '\0'; /* cut off the name there */
      conn->remote_port = curlx_ultous(port);
    }
    else if(!port)
      /* Browser behavior adaptation. If there's a colon with no digits after,
         just cut off the name there which makes us ignore the colon and just
         use the default port. Firefox and Chrome both do that. */
      *portptr = '\0';
  }
  return CURLE_OK;
}