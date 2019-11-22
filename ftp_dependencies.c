static CURLcode ftp_state_use_port(struct connectdata *conn,
                                   ftpport fcmd) /* start with this */

{
  CURLcode result = CURLE_OK;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct SessionHandle *data=conn->data;
  curl_socket_t portsock= CURL_SOCKET_BAD;
  char myhost[256] = "";

  struct Curl_sockaddr_storage ss;
  Curl_addrinfo *res, *ai;
  curl_socklen_t sslen;
  char hbuf[NI_MAXHOST];
  struct sockaddr *sa=(struct sockaddr *)&ss;
  struct sockaddr_in * const sa4 = (void *)sa;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 * const sa6 = (void *)sa;
#endif
  char tmp[1024];
  static const char mode[][5] = { "EPRT", "PORT" };
  int rc;
  int error;
  char *host=NULL;
  char *string_ftpport = data->set.str[STRING_FTPPORT];
  struct Curl_dns_entry *h=NULL;
  unsigned short port_min = 0;
  unsigned short port_max = 0;
  unsigned short port;

  char *addr = NULL;

  /* Step 1, figure out what is requested,
   * accepted format :
   * (ipv4|ipv6|domain|interface)?(:port(-range)?)?
   */

  if(data->set.str[STRING_FTPPORT] &&
     (strlen(data->set.str[STRING_FTPPORT]) > 1)) {

#ifdef ENABLE_IPV6
    size_t addrlen = INET6_ADDRSTRLEN > strlen(string_ftpport) ?
      INET6_ADDRSTRLEN : strlen(string_ftpport);
#else
    size_t addrlen = INET_ADDRSTRLEN > strlen(string_ftpport) ?
      INET_ADDRSTRLEN : strlen(string_ftpport);
#endif
    char *ip_start = string_ftpport;
    char *ip_end = NULL;
    char *port_start = NULL;
    char *port_sep = NULL;

    addr = calloc(addrlen+1, 1);
    if (!addr)
      return CURLE_OUT_OF_MEMORY;

#ifdef ENABLE_IPV6
    if(*string_ftpport == '[') {
      /* [ipv6]:port(-range) */
      ip_start = string_ftpport + 1;
      if((ip_end = strchr(string_ftpport, ']')) != NULL )
        strncpy(addr, ip_start, ip_end - ip_start);
    }
    else
#endif
      if( *string_ftpport == ':') {
        /* :port */
        ip_end = string_ftpport;
    }
    else if( (ip_end = strchr(string_ftpport, ':')) != NULL) {
        /* either ipv6 or (ipv4|domain|interface):port(-range) */
#ifdef ENABLE_IPV6
      if(Curl_inet_pton(AF_INET6, string_ftpport, sa6) == 1) {
        /* ipv6 */
        port_min = port_max = 0;
        strcpy(addr, string_ftpport);
        ip_end = NULL; /* this got no port ! */
      } else
#endif
      {
        /* (ipv4|domain|interface):port(-range) */
        strncpy(addr, string_ftpport, ip_end - ip_start );
      }
    }
    else
      /* ipv4|interface */
      strcpy(addr, string_ftpport);

    /* parse the port */
    if( ip_end != NULL ) {
      if((port_start = strchr(ip_end, ':')) != NULL) {
        port_min = curlx_ultous(strtoul(port_start+1, NULL, 10));
        if((port_sep = strchr(port_start, '-')) != NULL) {
          port_max = curlx_ultous(strtoul(port_sep + 1, NULL, 10));
        }
        else
          port_max = port_min;
      }
    }

    /* correct errors like:
     *  :1234-1230
     *  :-4711 , in this case port_min is (unsigned)-1,
     *           therefore port_min > port_max for all cases
     *           but port_max = (unsigned)-1
     */
    if(port_min > port_max )
      port_min = port_max = 0;


    if(*addr != '\0') {
      /* attempt to get the address of the given interface name */
      if(!Curl_if2ip(conn->ip_addr->ai_family, addr,
                     hbuf, sizeof(hbuf)))
        /* not an interface, use the given string as host name instead */
        host = addr;
      else
        host = hbuf; /* use the hbuf for host name */
    }else
      /* there was only a port(-range) given, default the host */
      host = NULL;
  } /* data->set.ftpport */

  if(!host) {
    /* not an interface and not a host name, get default by extracting
       the IP from the control connection */

    sslen = sizeof(ss);
    if(getsockname(conn->sock[FIRSTSOCKET], sa, &sslen)) {
      failf(data, "getsockname() failed: %s",
          Curl_strerror(conn, SOCKERRNO) );
      if (addr)
        free(addr);
      return CURLE_FTP_PORT_FAILED;
    }
    switch(sa->sa_family)
    {
#ifdef ENABLE_IPV6
      case AF_INET6:
        Curl_inet_ntop(sa->sa_family, &sa6->sin6_addr, hbuf, sizeof(hbuf));
        break;
#endif
      default:
        Curl_inet_ntop(sa->sa_family, &sa4->sin_addr, hbuf, sizeof(hbuf));
        break;
    }
    host = hbuf; /* use this host name */
  }

  /* resolv ip/host to ip */
  rc = Curl_resolv(conn, host, 0, &h);
  if(rc == CURLRESOLV_PENDING)
    (void)Curl_wait_for_resolv(conn, &h);
  if(h) {
    res = h->addr;
    /* when we return from this function, we can forget about this entry
       to we can unlock it now already */
    Curl_resolv_unlock(data, h);
  } /* (h) */
  else
    res = NULL; /* failure! */

  if (addr)
    free(addr);

  if (res == NULL) {
    failf(data, "Curl_resolv failed, we can not recover!");
    return CURLE_FTP_PORT_FAILED;
  }

  /* step 2, create a socket for the requested address */

  portsock = CURL_SOCKET_BAD;
  error = 0;
  for (ai = res; ai; ai = ai->ai_next) {
    /*
     * Workaround for AIX5 getaddrinfo() problem (it doesn't set ai_socktype):
     */
    if(ai->ai_socktype == 0)
      ai->ai_socktype = conn->socktype;

    portsock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if(portsock == CURL_SOCKET_BAD) {
      error = SOCKERRNO;
      continue;
    }
    break;
  }
  if(!ai) {
    failf(data, "socket failure: %s", Curl_strerror(conn, error));
    return CURLE_FTP_PORT_FAILED;
  }

  /* step 3, bind to a suitable local address */

  memcpy(sa, ai->ai_addr, ai->ai_addrlen);
  sslen = ai->ai_addrlen;

  for( port = port_min; port <= port_max; ) {
    if( sa->sa_family == AF_INET )
      sa4->sin_port = htons(port);
#ifdef ENABLE_IPV6
    else
      sa6->sin6_port = htons(port);
#endif
    /* Try binding the given address. */
    if(bind(portsock, sa, sslen) ) {
      /* It failed. */
      error = SOCKERRNO;
      if(error == EADDRNOTAVAIL) {

        /* The requested bind address is not local.  Use the address used for
         * the control connection instead and restart the port loop
         */
        failf(data, "bind(port=%hu) failed: %s", port,
              Curl_strerror(conn, error) );

        sslen = sizeof(ss);
        if(getsockname(conn->sock[FIRSTSOCKET], sa, &sslen)) {
          failf(data, "getsockname() failed: %s",
                Curl_strerror(conn, SOCKERRNO) );
          sclose(portsock);
          return CURLE_FTP_PORT_FAILED;
        }
        port = port_min;
        continue;
      }
      else if(error != EADDRINUSE && error != EACCES) {
        failf(data, "bind(port=%hu) failed: %s", port,
              Curl_strerror(conn, error) );
        sclose(portsock);
        return CURLE_FTP_PORT_FAILED;
      }
    }
    else
      break;

    port++;
  }

  /* maybe all ports were in use already*/
  if (port > port_max) {
    failf(data, "bind() failed, we ran out of ports!");
    sclose(portsock);
    return CURLE_FTP_PORT_FAILED;
  }

  /* get the name again after the bind() so that we can extract the
     port number it uses now */
  sslen = sizeof(ss);
  if(getsockname(portsock, (struct sockaddr *)sa, &sslen)) {
    failf(data, "getsockname() failed: %s",
          Curl_strerror(conn, SOCKERRNO) );
    sclose(portsock);
    return CURLE_FTP_PORT_FAILED;
  }

  /* step 4, listen on the socket */

  if(listen(portsock, 1)) {
    failf(data, "socket failure: %s", Curl_strerror(conn, SOCKERRNO));
    sclose(portsock);
    return CURLE_FTP_PORT_FAILED;
  }

  /* step 5, send the proper FTP command */

  /* get a plain printable version of the numerical address to work with
     below */
  Curl_printable_address(ai, myhost, sizeof(myhost));

#ifdef ENABLE_IPV6
  if(!conn->bits.ftp_use_eprt && conn->bits.ipv6)
    /* EPRT is disabled but we are connected to a IPv6 host, so we ignore the
       request and enable EPRT again! */
    conn->bits.ftp_use_eprt = TRUE;
#endif

  for (; fcmd != DONE; fcmd++) {

    if(!conn->bits.ftp_use_eprt && (EPRT == fcmd))
      /* if disabled, goto next */
      continue;

    if((PORT == fcmd) && sa->sa_family != AF_INET)
      /* PORT is ipv4 only */
      continue;

    switch (sa->sa_family) {
    case AF_INET:
      port = ntohs(sa4->sin_port);
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      port = ntohs(sa6->sin6_port);
      break;
#endif
    default:
      continue; /* might as well skip this */
    }

    if(EPRT == fcmd) {
      /*
       * Two fine examples from RFC2428;
       *
       * EPRT |1|132.235.1.2|6275|
       *
       * EPRT |2|1080::8:800:200C:417A|5282|
       */

      result = Curl_pp_sendf(&ftpc->pp, "%s |%d|%s|%hu|", mode[fcmd],
                             sa->sa_family == AF_INET?1:2,
                             myhost, port);
      if(result)
        return result;
      break;
    }
    else if(PORT == fcmd) {
      char *source = myhost;
      char *dest = tmp;

      /* translate x.x.x.x to x,x,x,x */
      while(source && *source) {
        if(*source == '.')
          *dest=',';
        else
          *dest = *source;
        dest++;
        source++;
      }
      *dest = 0;
      snprintf(dest, 20, ",%d,%d", (int)(port>>8), (int)(port&0xff));

      result = Curl_pp_sendf(&ftpc->pp, "%s %s", mode[fcmd], tmp);
      if(result)
        return result;
      break;
    }
  }

  /* store which command was sent */
  ftpc->count1 = fcmd;

  /* we set the secondary socket variable to this for now, it is only so that
     the cleanup function will close it in case we fail before the true
     secondary stuff is made */
  if(CURL_SOCKET_BAD != conn->sock[SECONDARYSOCKET])
    sclose(conn->sock[SECONDARYSOCKET]);
  conn->sock[SECONDARYSOCKET] = portsock;

  /* this tcpconnect assignment below is a hackish work-around to make the
     multi interface with active FTP work - as it will not wait for a
     (passive) connect in Curl_is_connected().

     The *proper* fix is to make sure that the active connection from the
     server is done in a non-blocking way. Currently, it is still BLOCKING.
  */
  conn->bits.tcpconnect = TRUE;

  state(conn, FTP_PORT);
  return result;
}

static CURLcode ftp_state_pasv_resp(struct connectdata *conn, int ftpcode)
{
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  CURLcode result;
  struct SessionHandle *data=conn->data;
  Curl_addrinfo *conninfo;
  struct Curl_dns_entry *addr=NULL;
  int rc;
  unsigned short connectport; /* the local port connect() should use! */
  unsigned short newport=0; /* remote port */
  bool connected;

  /* newhost must be able to hold a full IP-style address in ASCII, which
     in the IPv6 case means 5*8-1 = 39 letters */
#define NEWHOST_BUFSIZE 48
  char newhost[NEWHOST_BUFSIZE];
  char *str=&data->state.buffer[4];  /* start on the first letter */

  if((ftpc->count1 == 0) &&
     (ftpcode == 229)) {
    /* positive EPSV response */
    char *ptr = strchr(str, '(');
    if(ptr) {
      unsigned int num;
      char separator[4];
      ptr++;
      if(5  == sscanf(ptr, "%c%c%c%u%c",
                      &separator[0],
                      &separator[1],
                      &separator[2],
                      &num,
                      &separator[3])) {
        const char sep1 = separator[0];
        int i;

        /* The four separators should be identical, or else this is an oddly
           formatted reply and we bail out immediately. */
        for(i=1; i<4; i++) {
          if(separator[i] != sep1) {
            ptr=NULL; /* set to NULL to signal error */
            break;
          }
        }
        if(ptr) {
          newport = (unsigned short)(num & 0xffff);

          if(conn->bits.tunnel_proxy ||
             data->set.proxytype == CURLPROXY_SOCKS5 ||
             data->set.proxytype == CURLPROXY_SOCKS5_HOSTNAME ||
             data->set.proxytype == CURLPROXY_SOCKS4 ||
             data->set.proxytype == CURLPROXY_SOCKS4A)
            /* proxy tunnel -> use other host info because ip_addr_str is the
               proxy address not the ftp host */
            snprintf(newhost, sizeof(newhost), "%s", conn->host.name);
          else
            /* use the same IP we are already connected to */
            snprintf(newhost, NEWHOST_BUFSIZE, "%s", conn->ip_addr_str);
        }
      }
      else
        ptr=NULL;
    }
    if(!ptr) {
      failf(data, "Weirdly formatted EPSV reply");
      return CURLE_FTP_WEIRD_PASV_REPLY;
    }
  }
  else if((ftpc->count1 == 1) &&
          (ftpcode == 227)) {
    /* positive PASV response */
    int ip[4];
    int port[2];

    /*
     * Scan for a sequence of six comma-separated numbers and use them as
     * IP+port indicators.
     *
     * Found reply-strings include:
     * "227 Entering Passive Mode (127,0,0,1,4,51)"
     * "227 Data transfer will passively listen to 127,0,0,1,4,51"
     * "227 Entering passive mode. 127,0,0,1,4,51"
     */
    while(*str) {
      if(6 == sscanf(str, "%d,%d,%d,%d,%d,%d",
                      &ip[0], &ip[1], &ip[2], &ip[3],
                      &port[0], &port[1]))
        break;
      str++;
    }

    if(!*str) {
      failf(data, "Couldn't interpret the 227-response");
      return CURLE_FTP_WEIRD_227_FORMAT;
    }

    /* we got OK from server */
    if(data->set.ftp_skip_ip) {
      /* told to ignore the remotely given IP but instead use the one we used
         for the control connection */
      infof(data, "Skips %d.%d.%d.%d for data connection, uses %s instead\n",
            ip[0], ip[1], ip[2], ip[3],
            conn->ip_addr_str);
      if(conn->bits.tunnel_proxy ||
          data->set.proxytype == CURLPROXY_SOCKS5 ||
          data->set.proxytype == CURLPROXY_SOCKS5_HOSTNAME ||
          data->set.proxytype == CURLPROXY_SOCKS4 ||
          data->set.proxytype == CURLPROXY_SOCKS4A)
        /* proxy tunnel -> use other host info because ip_addr_str is the
           proxy address not the ftp host */
        snprintf(newhost, sizeof(newhost), "%s", conn->host.name);
      else
        snprintf(newhost, sizeof(newhost), "%s", conn->ip_addr_str);
    }
    else
      snprintf(newhost, sizeof(newhost),
               "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    newport = (unsigned short)(((port[0]<<8) + port[1]) & 0xffff);
  }
  else if(ftpc->count1 == 0) {
    /* EPSV failed, move on to PASV */

    /* disable it for next transfer */
    conn->bits.ftp_use_epsv = FALSE;
    infof(data, "disabling EPSV usage\n");

    PPSENDF(&ftpc->pp, "PASV", NULL);
    ftpc->count1++;
    /* remain in the FTP_PASV state */
    return result;
  }
  else {
    failf(data, "Bad PASV/EPSV response: %03d", ftpcode);
    return CURLE_FTP_WEIRD_PASV_REPLY;
  }

  if(data->set.str[STRING_PROXY] && *data->set.str[STRING_PROXY]) {
    /*
     * This is a tunnel through a http proxy and we need to connect to the
     * proxy again here.
     *
     * We don't want to rely on a former host lookup that might've expired
     * now, instead we remake the lookup here and now!
     */
    rc = Curl_resolv(conn, conn->proxy.name, (int)conn->port, &addr);
    if(rc == CURLRESOLV_PENDING)
      /* BLOCKING, ignores the return code but 'addr' will be NULL in
         case of failure */
      (void)Curl_wait_for_resolv(conn, &addr);

    connectport =
      (unsigned short)conn->port; /* we connect to the proxy's port */

    if(!addr) {
      failf(data, "Can't resolve proxy host %s:%hu",
            conn->proxy.name, connectport);
      return CURLE_FTP_CANT_GET_HOST;
    }
  }
  else {
    /* normal, direct, ftp connection */
    rc = Curl_resolv(conn, newhost, newport, &addr);
    if(rc == CURLRESOLV_PENDING)
      /* BLOCKING */
      (void)Curl_wait_for_resolv(conn, &addr);

    connectport = newport; /* we connect to the remote port */

    if(!addr) {
      failf(data, "Can't resolve new host %s:%hu", newhost, connectport);
      return CURLE_FTP_CANT_GET_HOST;
    }
  }

  result = Curl_connecthost(conn,
                            addr,
                            &conn->sock[SECONDARYSOCKET],
                            &conninfo,
                            &connected);

  Curl_resolv_unlock(data, addr); /* we're done using this address */

  if(result && ftpc->count1 == 0 && ftpcode == 229) {
    infof(data, "got positive EPSV response, but can't connect. "
          "Disabling EPSV\n");
    /* disable it for next transfer */
    conn->bits.ftp_use_epsv = FALSE;
    data->state.errorbuf = FALSE; /* allow error message to get rewritten */
    PPSENDF(&ftpc->pp, "PASV", NULL);
    ftpc->count1++;
    /* remain in the FTP_PASV state */
    return result;
 }

  if(result)
    return result;

  conn->bits.tcpconnect = connected; /* simply TRUE or FALSE */

  /*
   * When this is used from the multi interface, this might've returned with
   * the 'connected' set to FALSE and thus we are now awaiting a non-blocking
   * connect to connect and we should not be "hanging" here waiting.
   */

  if(data->set.verbose)
    /* this just dumps information about this second connection */
    ftp_pasv_verbose(conn, conninfo, newhost, connectport);

  switch(data->set.proxytype) {
    /* FIX: this MUST wait for a proper connect first if 'connected' is
     * FALSE */
  case CURLPROXY_SOCKS5:
  case CURLPROXY_SOCKS5_HOSTNAME:
    result = Curl_SOCKS5(conn->proxyuser, conn->proxypasswd, newhost, newport,
                         SECONDARYSOCKET, conn);
    break;
  case CURLPROXY_SOCKS4:
    result = Curl_SOCKS4(conn->proxyuser, newhost, newport,
                         SECONDARYSOCKET, conn, FALSE);
    break;
  case CURLPROXY_SOCKS4A:
    result = Curl_SOCKS4(conn->proxyuser, newhost, newport,
                         SECONDARYSOCKET, conn, TRUE);
    break;
  case CURLPROXY_HTTP:
  case CURLPROXY_HTTP_1_0:
    /* do nothing here. handled later. */
    break;
  default:
    failf(data, "unknown proxytype option given");
    result = CURLE_COULDNT_CONNECT;
    break;
  }

  if(conn->bits.tunnel_proxy && conn->bits.httpproxy) {
    /* FIX: this MUST wait for a proper connect first if 'connected' is
     * FALSE */

    /* BLOCKING */
    /* We want "seamless" FTP operations through HTTP proxy tunnel */

    /* Curl_proxyCONNECT is based on a pointer to a struct HTTP at the member
     * conn->proto.http; we want FTP through HTTP and we have to change the
     * member temporarily for connecting to the HTTP proxy. After
     * Curl_proxyCONNECT we have to set back the member to the original struct
     * FTP pointer
     */
    struct HTTP http_proxy;
    struct FTP *ftp_save = data->state.proto.ftp;
    memset(&http_proxy, 0, sizeof(http_proxy));
    data->state.proto.http = &http_proxy;

    result = Curl_proxyCONNECT(conn, SECONDARYSOCKET, newhost, newport);

    data->state.proto.ftp = ftp_save;

    if(CURLE_OK != result)
      return result;
  }


  state(conn, FTP_STOP); /* this phase is completed */

  return result;
}

static CURLcode ftp_done(struct connectdata *conn, CURLcode status,
                              bool premature)
{
  struct SessionHandle *data = conn->data;
  struct FTP *ftp = data->state.proto.ftp;
  struct ftp_conn *ftpc = &conn->proto.ftpc;
  struct pingpong *pp = &ftpc->pp;
  ssize_t nread;
  int ftpcode;
  CURLcode result=CURLE_OK;
  bool was_ctl_valid = ftpc->ctl_valid;
  char *path;
  const char *path_to_use = data->state.path;

  if(!ftp)
    /* When the easy handle is removed from the multi while libcurl is still
     * trying to resolve the host name, it seems that the ftp struct is not
     * yet initialized, but the removal action calls Curl_done() which calls
     * this function. So we simply return success if no ftp pointer is set.
     */
    return CURLE_OK;

  switch(status) {
  case CURLE_BAD_DOWNLOAD_RESUME:
  case CURLE_FTP_WEIRD_PASV_REPLY:
  case CURLE_FTP_PORT_FAILED:
  case CURLE_FTP_COULDNT_SET_TYPE:
  case CURLE_FTP_COULDNT_RETR_FILE:
  case CURLE_UPLOAD_FAILED:
  case CURLE_REMOTE_ACCESS_DENIED:
  case CURLE_FILESIZE_EXCEEDED:
  case CURLE_REMOTE_FILE_NOT_FOUND:
  case CURLE_WRITE_ERROR:
    /* the connection stays alive fine even though this happened */
    /* fall-through */
  case CURLE_OK: /* doesn't affect the control connection's status */
    if(!premature) {
      ftpc->ctl_valid = was_ctl_valid;
      break;
    }
    /* until we cope better with prematurely ended requests, let them
     * fallback as if in complete failure */
  default:       /* by default, an error means the control connection is
                    wedged and should not be used anymore */
    ftpc->ctl_valid = FALSE;
    ftpc->cwdfail = TRUE; /* set this TRUE to prevent us to remember the
                             current path, as this connection is going */
    conn->bits.close = TRUE; /* marked for closure */
    result = status;      /* use the already set error code */
    break;
  }

  /* now store a copy of the directory we are in */
  if(ftpc->prevpath)
    free(ftpc->prevpath);

  if(data->set.wildcardmatch) {
    if(data->set.chunk_end && ftpc->file) {
      data->set.chunk_end(data->wildcard.customptr);
    }
    ftpc->known_filesize = -1;
  }

  /* get the "raw" path */
  path = curl_easy_unescape(data, path_to_use, 0, NULL);
  if(!path) {
    /* out of memory, but we can limp along anyway (and should try to
     * since we're in the out of memory cleanup path) */
    ftpc->prevpath = NULL; /* no path */
  }
  else {
    size_t flen = ftpc->file?strlen(ftpc->file):0; /* file is "raw" already */
    size_t dlen = strlen(path)-flen;
    if(!ftpc->cwdfail) {
      if(dlen && (data->set.ftp_filemethod != FTPFILE_NOCWD)) {
        ftpc->prevpath = path;
        if(flen)
          /* if 'path' is not the whole string */
          ftpc->prevpath[dlen]=0; /* terminate */
      }
      else {
        /* we never changed dir */
        ftpc->prevpath=strdup("");
        free(path);
      }
      if(ftpc->prevpath)
        infof(data, "Remembering we are in dir \"%s\"\n", ftpc->prevpath);
    }
    else {
      ftpc->prevpath = NULL; /* no path */
      free(path);
    }
  }
  /* free the dir tree and file parts */
  freedirs(ftpc);

  /* shut down the socket to inform the server we're done */

#ifdef _WIN32_WCE
  shutdown(conn->sock[SECONDARYSOCKET],2);  /* SD_BOTH */
#endif

  if(conn->sock[SECONDARYSOCKET] != CURL_SOCKET_BAD) {
    if(!result && ftpc->dont_check && data->req.maxdownload > 0)
      /* partial download completed */
      result = Curl_pp_sendf(pp, "ABOR");

    if(conn->ssl[SECONDARYSOCKET].use) {
      /* The secondary socket is using SSL so we must close down that part
         first before we close the socket for real */
      Curl_ssl_close(conn, SECONDARYSOCKET);

      /* Note that we keep "use" set to TRUE since that (next) connection is
         still requested to use SSL */
    }
    if(CURL_SOCKET_BAD != conn->sock[SECONDARYSOCKET]) {
      sclose(conn->sock[SECONDARYSOCKET]);
      conn->sock[SECONDARYSOCKET] = CURL_SOCKET_BAD;
    }
  }

  if(!result && (ftp->transfer == FTPTRANSFER_BODY) && ftpc->ctl_valid &&
     pp->pending_resp && !premature) {
    /*
     * Let's see what the server says about the transfer we just performed,
     * but lower the timeout as sometimes this connection has died while the
     * data has been transferred. This happens when doing through NATs etc that
     * abandon old silent connections.
     */
    long old_time = pp->response_time;

    pp->response_time = 60*1000; /* give it only a minute for now */
    pp->response = Curl_tvnow(); /* timeout relative now */

    result = Curl_GetFTPResponse(&nread, conn, &ftpcode);

    pp->response_time = old_time; /* set this back to previous value */

    if(!nread && (CURLE_OPERATION_TIMEDOUT == result)) {
      failf(data, "control connection looks dead");
      ftpc->ctl_valid = FALSE; /* mark control connection as bad */
      conn->bits.close = TRUE; /* mark for closure */
    }

    if(result)
      return result;

    if(ftpc->dont_check && data->req.maxdownload > 0) {
      /* we have just sent ABOR and there is no reliable way to check if it was
       * successful or not; we have to close the connection now */
      infof(data, "partial download completed, closing connection\n");
      conn->bits.close = TRUE; /* mark for closure */
      return result;
    }

    if(!ftpc->dont_check) {
      /* 226 Transfer complete, 250 Requested file action okay, completed. */
      if((ftpcode != 226) && (ftpcode != 250)) {
        failf(data, "server did not report OK, got %d", ftpcode);
        result = CURLE_PARTIAL_FILE;
      }
    }
  }

  if(result || premature)
    /* the response code from the transfer showed an error already so no
       use checking further */
    ;
  else if(data->set.upload) {
    if((-1 != data->set.infilesize) &&
       (data->set.infilesize != *ftp->bytecountp) &&
       !data->set.crlf &&
       (ftp->transfer == FTPTRANSFER_BODY)) {
      failf(data, "Uploaded unaligned file size (%" FORMAT_OFF_T
            " out of %" FORMAT_OFF_T " bytes)",
            *ftp->bytecountp, data->set.infilesize);
      result = CURLE_PARTIAL_FILE;
    }
  }
  else {
    if((-1 != data->req.size) &&
       (data->req.size != *ftp->bytecountp) &&
#ifdef CURL_DO_LINEEND_CONV
       /* Most FTP servers don't adjust their file SIZE response for CRLFs, so
        * we'll check to see if the discrepancy can be explained by the number
        * of CRLFs we've changed to LFs.
        */
       ((data->req.size + data->state.crlf_conversions) !=
        *ftp->bytecountp) &&
#endif /* CURL_DO_LINEEND_CONV */
       (data->req.maxdownload != *ftp->bytecountp)) {
      failf(data, "Received only partial file: %" FORMAT_OFF_T " bytes",
            *ftp->bytecountp);
      result = CURLE_PARTIAL_FILE;
    }
    else if(!ftpc->dont_check &&
            !*ftp->bytecountp &&
            (data->req.size>0)) {
      failf(data, "No data was received!");
      result = CURLE_FTP_COULDNT_RETR_FILE;
    }
  }

  /* clear these for next connection */
  ftp->transfer = FTPTRANSFER_BODY;
  ftpc->dont_check = FALSE;

  /* Send any post-transfer QUOTE strings? */
  if(!status && !result && !premature && data->set.postquote)
    result = ftp_sendquote(conn, data->set.postquote);

  return result;
}