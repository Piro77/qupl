/*************************************************************************************************
 * CGI script for file uploader
 *                                                      Copyright (C) 2000-2003 Mikio Hirabayashi
 * This file is part of QDBM, Quick Database Manager.
 * QDBM is free software; you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation; either version
 * 2.1 of the License or any later version.  QDBM is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 * You should have received a copy of the GNU Lesser General Public License along with QDBM; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307 USA.
 *************************************************************************************************/


#include <depot.h>
#include <cabin.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#undef TRUE
#define TRUE           1                 /* boolean true */
#undef FALSE
#define FALSE          0                 /* boolean false */

#define CONFFILE    "qupl.conf"          /* name of the configuration file */
#define DEFENC      "US-ASCII"           /* default encoding */
#define DEFLANG     "en"                 /* default language */
#define DEFTITLE    "File Uploader"      /* default title */
#define DEFDATADIR  "qupldir"            /* directory containing files */
#define RDATAMAX    67108864             /* max size of data to read */
#define SESSIONSTR   "quplsession"	


/* global variables */
const char *scriptname;                  /* name of the script */
const char *enc;                         /* encoding of the page */
const char *lang;                        /* language of the page */
const char *title;                       /* title of the page */
int quota;                               /* limit of the total size */


/* function prototypes */
int main(int argc, char **argv);
const char *skiplabel(const char *str);
void htmlprintf(const char *format, ...);
int getdirsize(const char *path);
const char *datestr(time_t t);
const char *gettype(const char *path);
char *chkcookie(char *datadir,char **session);
CBMAP *getparams(void);
CBLIST *chkuser(char *id,char *pass,char *datadir);
char *getsessionid();
int createsession(char *id,char *sessionid,char *datadir);
void setcookie(char *name,char *value,char *domain,int kigen,char *path);
CBMAP *getcookie(void);
char *chksession(char *id,char *datadir);
int removesession(char *sessionid,char *datadir);
char *makeuploadtmpfile(char *dir, int no);
int splituploadtmp(char *bound,char *dir,char *fname);
char *gettmptoreal(char *dir,char *infname,char **outfname);
int creatfiledb(char *hash,char *fname,char *updid,char *datadir);
CBLIST *getuser(char *id,char *datadir);
CBLIST *gethash2filename(char *hash);
int removefilehash(char *hash);
CBLIST *listmyfiles(char *id);


void disp_login(char *Login);
void self_redirect(int sec,char *message,const char *myself,const char *enc);
void chktmp(char *dir);


/* main routine */
int main(int argc, char **argv){
  CBLIST *lines, *parts, *files,*userinfo,*fileinfo;
  CBMAP *params;
  FILE *ifp;
  const char *tmp, *datadir,  *body, *sname,*ses;
  char *tmpfname0,*tmpfname1;
  char *wp, *bound, *cdata, *filedata, *filename, *ebuf, *dbuf, *getname, *delname, numbuf[32];
  char *filehash,*userid;
  int i, clen, blen, filesize, c, sdir, ssize, total;
  char *id,*pass;
  time_t stime;
  /* set configurations */
  cbstdiobin();
  scriptname = argv[0];
  if((tmp = getenv("SCRIPT_NAME")) != NULL) scriptname = tmp;
  enc = NULL;
  lang = NULL;
  title = NULL;
  datadir = NULL;
  userid = NULL;
  quota = 0;
  if((lines = cbreadlines(CONFFILE)) != NULL){
    for(i = 0; i < cblistnum(lines); i++){
      tmp = cblistval(lines, i, NULL);
      if(cbstrfwmatch(tmp, "encoding:")){
        enc = skiplabel(tmp);
      } else if(cbstrfwmatch(tmp, "lang:")){
        lang = skiplabel(tmp);
      } else if(cbstrfwmatch(tmp, "title:")){
        title = skiplabel(tmp);
      } else if(cbstrfwmatch(tmp, "datadir:")){
        datadir = skiplabel(tmp);
      } else if(cbstrfwmatch(tmp, "quota:")){
        quota = atoi(skiplabel(tmp));
      }
    }
  }
  if(!enc) enc = DEFENC;
  if(!lang) lang = DEFLANG;
  if(!title) title = DEFTITLE;
  if(!datadir) datadir = DEFDATADIR;
  if(quota < 0) quota = 0;
  /* read parameters */
  filedata = NULL;
  filesize = 0;
  filename = NULL;
  filehash = NULL;
  getname = NULL;
  delname = NULL;
  ses = NULL;
  id =NULL;
  pass = NULL;

  if((tmp = getenv("QUERY_STRING")) != NULL && (tmp = strstr(tmp, "mode=login"))){
    params = getparams();
    if((tmp = cbmapget(params, "id", -1, NULL)) != NULL) id = (char *)tmp;
    if((tmp = cbmapget(params, "pass", -1, NULL)) != NULL) pass = (char *)tmp;
    userinfo = chkuser(id,pass,(char *)datadir);
    if (userinfo==NULL) {
      char *msg,*encid;
      msg = cbmalloc(100);
      encid = cburlencode(id,-1);
      sprintf(msg,"Login Error %s\n",encid);
      disp_login(msg);
      free(msg);
      cbfree(encid);
      return 0;
    }
    ses = getsessionid();
    if (createsession(id,(char *)ses,(char *)datadir)==FALSE) {
      /*error*/
     self_redirect(10,"Session Create Error",scriptname,enc);
     return 0;
    }
    else {
    /* セッションDB を作ったら　クッキーを発行しリダイレクト */
      setcookie(SESSIONSTR,(char *)ses,getenv("HTTP_HOST"),864000,"/cgi-bin/");
      self_redirect(1,NULL,scriptname,enc);
      return 0;
    }
  }

  /* クッキー確認 */
  userid=chkcookie((char *)datadir,(char **)&ses);
  if (userid==NULL) {
    char *msg;
    msg = cbmalloc(100);
    sprintf(msg,"Login  [%s]\n",ses);
     disp_login(msg);
    free(msg);
    return 0;
  }
  userinfo = getuser(userid,(char *)datadir);

  if((tmp = getenv("REQUEST_METHOD")) != NULL && !strcmp(tmp, "POST") &&
     (tmp = getenv("CONTENT_LENGTH")) != NULL && (clen = atoi(tmp)) > 0 &&
     (tmp = getenv("CONTENT_TYPE")) != NULL && cbstrfwmatch(tmp, "multipart/form-data") &&
     (tmp = strstr(tmp, "boundary=")) != NULL){
    tmp += 9;
    if(*tmp == '"') tmp++;
    bound = cbmemdup(tmp, -1);
    if((wp = strchr(bound, ';')) != NULL) *wp = '\0';
    chktmp(DEFDATADIR);
    tmpfname0 = makeuploadtmpfile(DEFDATADIR,0);
    tmpfname1 = makeuploadtmpfile(DEFDATADIR,1);
    if (splituploadtmp(bound,DEFDATADIR,tmpfname0)==0) {
      self_redirect(10,"Upload File Error(Split)",scriptname,enc);
      unlink(tmpfname0);
      unlink(tmpfname1);
      free(tmpfname0);
      free(tmpfname1);
      return 0;
    }
    filehash = gettmptoreal(DEFDATADIR,tmpfname1, &filename);
    if (filehash==NULL) {
      self_redirect(10,"Upload File Error",scriptname,enc);
      unlink(tmpfname0);
      unlink(tmpfname1);
      free(tmpfname0);
      free(tmpfname1);
      return 0;
    }
    if (creatfiledb(DEFDATADIR,filehash,filename,userid)!=TRUE) {
      self_redirect(10,"filedb error(create or write)",scriptname,enc);
      return 0;
    }
    unlink(tmpfname0);
    unlink(tmpfname1);
    free(filehash);
    free(tmpfname0);
    free(tmpfname1);

  } else if((tmp = getenv("PATH_INFO")) != NULL){
    if(tmp[0] == '/') tmp++;
    getname = cburldecode(tmp, NULL);
    if(cbstrfwmatch(getname, "../") || strstr(getname, "/../") != NULL){
      free(getname);
      getname = NULL;
    }
  } else if((tmp = getenv("QUERY_STRING")) != NULL && (tmp = strstr(tmp, "delfile="))){
    tmp += 8;
    delname = cburldecode(tmp, NULL);
    if(cbstrfwmatch(delname, "../") || strstr(delname, "/../") != NULL){
      free(delname);
      delname = NULL;
    }
  } else if((tmp = getenv("QUERY_STRING")) != NULL && (tmp = strstr(tmp, "mode=logout"))){
    removesession((char *)ses,(char *)datadir);
    setcookie(SESSIONSTR,"",getenv("HTTP_HOST"),864000,"/cgi-bin/");
    self_redirect(1,NULL,scriptname,enc);
    return(0);
  } else if((tmp = getenv("QUERY_STRING")) != NULL && (tmp = strstr(tmp, "mode=chpass"))){
    char *old;
    char *new1;
    char *new2;
    char *msg;
    char *rdr;
    old  = NULL;
    new1 = NULL;
    new2 = NULL;
    rdr = cbsprintf("%s?%s",scriptname,getenv("QUERY_STRING"));
    params = getparams();
    if((tmp = cbmapget(params, "oldpass", -1, NULL)) != NULL)  old  = (char *)tmp;
    if((tmp = cbmapget(params, "newpass1", -1, NULL)) != NULL) new1 = (char *)tmp;
    if((tmp = cbmapget(params, "newpass2", -1, NULL)) != NULL) new2 = (char *)tmp;
    /* パスワード未入力・新パスワード(1,2)不一致・旧パスワード不一致*/
    msg = cbsprintf("Change Password for %s",userid);
    if (old) {
      /* 旧パスワードチェック */
      if (new1 && new2) {
        if (strcmp(new1,new2)==0) {
           msg = cbsprintf("Change Password for %s Complete Please Re Login",userid,new1);
           self_redirect(10,msg,scriptname,enc);
           return 0;
        }
      }
    }
    disp_chpass(msg);
    return(0);
  }

  if(getname){
    /* send data of the file */
    if (chdir(datadir)==0) {
      fileinfo = gethash2filename(getname);
      if (fileinfo) {
        getname = (char *)cblistval(fileinfo,0,NULL);
      }
    }
    ifp = fopen(getname,"rb");
    if(ifp != NULL){
      char *rbuf;
      printf("Content-Disposition: attachment; filename=\"%s\"\r\n",getname);
      printf("Content-Type: %s\r\n", "application/octet-stream");
      printf("Cache-Control: no-cache, must-revalidate\r\n");
      printf("Pragma: no-cache\r\n");
      printf("\r\n");
/*
      while((c = fgetc(ifp)) != EOF){
        putchar(c);
      }
*/
      rbuf = cbmalloc(RDATAMAX);
      while(1) {
        clen = fread(rbuf,1,RDATAMAX,ifp);
        fwrite(rbuf,1,clen,stdout);
        if (feof(ifp)) break;
      }
      cbfree(rbuf);
      fclose(ifp);
    } else {
      printf("Status: 404 Not Found\r\n");
      printf("Content-Type: text/plain; charset=%s\r\n", enc);
      printf("Cache-Control: no-cache, must-revalidate\r\n");
      printf("Pragma: no-cache\r\n");
      printf("\r\n");
      printf("Not Found\n");
      printf("%s\n", getname);
    }
  } else {
    /* output headers */
    printf("Content-Type: text/html; charset=%s\r\n", enc);
    printf("Cache-Control: no-cache, must-revalidate\r\n");
    printf("Pragma: no-cache\r\n");
    printf("\r\n");
    htmlprintf("<?xml version=\"1.0\" encoding=\"%s\"?>\n", enc);
    htmlprintf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" "
               "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n");
    htmlprintf("<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"%s\" lang=\"%s\">\n",
               lang, lang);
    htmlprintf("<head>\n");
    htmlprintf("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\" />\n", enc);
    htmlprintf("<meta http-equiv=\"Content-Style-Type\" content=\"text/css\" />\n");
    htmlprintf("<link rel=\"contents\" href=\"./\" />\n");
    htmlprintf("<title>%@</title>\n", title);
    htmlprintf("<style type=\"text/css\">\n");
    htmlprintf("body { background-color: #eeeeee; color: #111111;"
               " margin: 1em 1em; padding: 1em 1em; }\n");
    htmlprintf("hr { margin: 1.5em 0em; height: 1pt;"
               " color: #999999; background-color: #999999; border: none; }\n");
    htmlprintf("a { color: #0022aa; text-decoration: none; }\n");
    htmlprintf("a:hover { color: #1144ff; text-decoration: underline; }\n");
    htmlprintf("table { border-collapse: collapse; }\n");
    htmlprintf("th,td { text-align: left; }\n");
    htmlprintf("th { padding: 0.1em 0.4em; border: none;"
               " font-size: smaller; font-weight: normal; }\n");
    htmlprintf("td { padding: 0.2em 0.5em; background-color: #ddddee;"
               " border: 1pt solid #888888; }\n");
    htmlprintf(".note { margin: 0.5em 0.5em; text-align: right; }\n");
    htmlprintf("</style>\n");
    htmlprintf("</head>\n");
    htmlprintf("<body>\n");
    htmlprintf("<h1>%@ [%s][%s][%s]</h1>\n", title,userid,cblistval(userinfo,1,NULL),cblistval(userinfo,2,NULL));

    htmlprintf("<div class=\"note\">\n");
    htmlprintf("  <a href=\"%s?mode=logout\">[LOGOUT]</a>\n", scriptname);
    htmlprintf("  <a href=\"%s?mode=chpass\">[ChangePassword]</a>\n", scriptname);
    htmlprintf("</div>\n");
    htmlprintf("<hr />\n");

    htmlprintf("<form method=\"post\" enctype=\"multipart/form-data\" action=\"%s\">\n",
               scriptname);
    htmlprintf("<div>\n");
    htmlprintf("<input type=\"file\" name=\"file\" size=\"64\""
               " tabindex=\"1\" accesskey=\"0\" />\n");
/*
    htmlprintf("<input type=\"text\" name=\"comment\" size=\"64\""
               " tabindex=\"2\" accesskey=\"1\" />\n");
*/
    htmlprintf("<input type=\"submit\" value=\"UPLOAD\" tabindex=\"3\" accesskey=\"3\" />\n");
    htmlprintf("<a href=\"%s\">[RELOAD]</a>\n", scriptname);
    htmlprintf("</div>\n");
    htmlprintf("</form>\n");
    htmlprintf("<hr />\n");
    /* change the currnt directory */
    if(chdir(datadir) == -1){
      htmlprintf("<p>Changing the current directory was failed.</p>\n");
      htmlprintf("<hr />\n");
    } else {
      /* save the file */
      if(filedata && filename){
        sname = filename;
        if((ebuf = cbiconv(filename, -1, enc, "UTF-8", NULL, NULL)) != NULL) sname = ebuf;
        if((tmp = strrchr(sname, '/')) != NULL) sname = tmp + 1;
        if((tmp = strrchr(sname, '\\')) != NULL) sname = tmp + 1;
        if(ebuf){
          while((tmp = strstr(sname, "\xc2\xa5")) != NULL){
            sname = tmp + 2;
          }
        }
        dbuf = NULL;
        if(ebuf && (dbuf = cbiconv(sname, -1, "UTF-8", enc, NULL, NULL)) != NULL) sname = dbuf;
        if(getdirsize(".") + filesize > quota){
          htmlprintf("<p>Exceeding the quota. -- %@</p>\n", sname);
        } else if(!cbwritefile(sname, filedata, filesize)){
          htmlprintf("<p>Uploading was failed. -- %@</p>\n", sname);
        } else {
          htmlprintf("<p>Uploading was succeeded. -- %@</p>\n", sname);
        }
        htmlprintf("<hr />\n");
        free(dbuf);
        free(ebuf);
      } else if(delname){
        /* delete the file */
        if(delname && removefilehash(delname) == TRUE){
          htmlprintf("<p>Deleting was succeeded. -- %@</p>\n", delname);
        } else {
          htmlprintf("<p>Deleting was failed. -- %@</p>\n", delname);
        }
        htmlprintf("<hr />\n");
      }
      /* show the file list */
      if((files = listmyfiles(userid)) != NULL){
        cblistsort(files);
        htmlprintf("<table summary=\"files\">\n");
        htmlprintf("<tr>\n");
        htmlprintf("<th abbr=\"name\">Name</th>\n");
        htmlprintf("<th abbr=\"size\">Size</th>\n");
        htmlprintf("<th abbr=\"mtime\">Modified Time</th>\n");
        htmlprintf("<th abbr=\"hash\">Key</th>\n");
        htmlprintf("<th abbr=\"IP\">Download IP</th>\n");
        htmlprintf("<th abbr=\"dtime\">Download Date</th>\n");
        htmlprintf("<th abbr=\"act\">Actions</th>\n");
        htmlprintf("</tr>\n");
        for(i = 0; i < cblistnum(files); i++){
          sname = cblistval(files, i, NULL);
          fileinfo = cbsplit(sname,-1,",");
        
          if(!cbfilestat(cblistval(fileinfo,1,NULL), &sdir, &ssize, &stime) || sdir) continue;
          htmlprintf("<tr>\n");
          htmlprintf("<td>%@</td>\n", cburldecode(cblistval(fileinfo,1,NULL),NULL));
          htmlprintf("<td>%d</td>\n", ssize);
          htmlprintf("<td>%@</td>\n", datestr(stime));
          htmlprintf("<td>%@</td>\n", cblistval(fileinfo,0,NULL));
          htmlprintf("<td>%@</td>\n", cblistval(fileinfo,6,NULL));
          htmlprintf("<td>%@</td>\n", cblistval(fileinfo,7,NULL));
          htmlprintf("<td>\n");
          htmlprintf("<a href=\"%s/%?\">[GET]</a>", scriptname, cblistval(fileinfo,0,NULL));
          htmlprintf(" / ");
          htmlprintf("<a href=\"%s?delfile=%?\">[DEL]</a>", scriptname, cblistval(fileinfo,0,NULL));
          htmlprintf("</td>\n");
          htmlprintf("</tr>\n");
        }
        htmlprintf("</table>\n");
        cblistclose(files);
        total = getdirsize(".");
        sprintf(numbuf, "%.2f%%", (total * 100.0) / quota);
        htmlprintf("<div class=\"note\">Capacity: %@ (%d/%d)</div>\n", numbuf, total, quota);
      } else {
        htmlprintf("<p>Listing files in the data directory was failed.</p>\n");
      }
      htmlprintf("<hr />\n");
    }
    /* output footers */
    htmlprintf("<div class=\"note\">Powered by QDBM %@.</div>\n", dpversion);
    htmlprintf("</body>\n");
    htmlprintf("</html>\n");
  }
  /* release resources */
  if(getname) free(getname);
  if(delname) free(delname);
  if(filename) free(filename);
  if(filedata) free(filedata);
  if(lines) cblistclose(lines);
  return 0;
}


const char *skiplabel(const char *str){
  if(!(str = strchr(str, ':'))) return str;
  str++;
  while(*str != '\0' && (*str == ' ' || *str == '\t')){
    str++;
  }
  return str;
}


/* get the total size of files in a directory */
int getdirsize(const char *path){
  CBLIST *files;
  const char *sname;
  int i, total, isdir, size;
  total = 0;
  if((files = cbdirlist(path)) != NULL){
    for(i = 0; i < cblistnum(files); i++){
      sname = cblistval(files, i, NULL);
      if(!strcmp(sname, ".") || !strcmp(sname, "..")) continue;
      if(!cbfilestat(sname, &isdir, &size, NULL) || isdir) continue;
      total += size;
    }
  }
  return total;
}



/* get the media type of a file */
const char *gettype(const char *path){
  char *types[] = {
    ".txt", "text/plain", ".asc", "text/plain", ".html", "text/html", ".htm", "text/html",
    ".mht", "message/rfc822", ".sgml", "application/sgml", ".sgm", "application/sgml",
    ".xml", "application/xml", ".rtf", "application/rtf", ".pdf", "application/pdf",
    ".doc", "application/msword", ".xls", "application/vnd.ms-excel",
    ".ppt", "application/vnd.ms-powerpoint", ".xdw", "application/vnd.fujixerox.docuworks",
    ".zip", "application/zip", ".tar", "application/x-tar", ".gz", "application/x-gzip",
    ".png", "image/png", ".gif", "image/gif", ".jpg", "image/jpeg", ".jpeg", "image/jpeg",
    ".tif", "image/tiff", ".tiff", "image/tiff", ".bmp", "image/bmp", ".mid", "audio/midi",
    ".midi", "audio/midi", ".mp3", "audio/mpeg", ".wav", "audio/x-wav", ".mpg", "video/mpeg",
    ".mpeg", "video/mpeg", NULL
  };
  int i;
  for(i = 0; types[i]; i += 2){
    if(cbstrbwimatch(path, types[i])) return types[i+1];
  }
  return "application/octet-stream";
}

char *chkcookie(char *datadir,char **ses)
{
  CBMAP *params;
  char  *session=NULL;
  const char  *tmp=NULL;
  char  *id=NULL;
  params = getcookie();
  if (params==NULL) {
    return NULL;
  }
  if((tmp = cbmapget(params, (const char *)SESSIONSTR, -1, NULL)) != NULL) session = (char *)tmp;
  if (session == NULL) {
    return NULL;
  }
  /* セッションIDが有効か確認 */
  id = chksession(session,datadir);
  if (id == NULL) {
    return NULL;
  }
  *ses = session;
  return id;
}

void disp_login(char *Login)
{
    printf("Content-Type: text/html; charset=%s\r\n", enc);
    printf("Cache-Control: no-cache, must-revalidate\r\n");
    printf("Pragma: no-cache\r\n");
    printf("\r\n");
    htmlprintf("<?xml version=\"1.0\" encoding=\"%s\"?>\n", enc);
    htmlprintf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" "
               "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n");
    htmlprintf("<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"%s\" lang=\"%s\">\n",
               lang, lang);
    htmlprintf("<head>\n");
    htmlprintf("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\" />\n", enc);
    htmlprintf("<meta http-equiv=\"Content-Style-Type\" content=\"text/css\" />\n");
    htmlprintf("<link rel=\"contents\" href=\"./\" />\n");
    htmlprintf("<title>%@</title>\n", Login);
    htmlprintf("<style type=\"text/css\">\n");
    htmlprintf("body { background-color: #eeeeee; color: #111111;"
               " margin: 1em 1em; padding: 1em 1em; }\n");
    htmlprintf("hr { margin: 1.5em 0em; height: 1pt;"
               " color: #999999; background-color: #999999; border: none; }\n");
    htmlprintf("a { color: #0022aa; text-decoration: none; }\n");
    htmlprintf("a:hover { color: #1144ff; text-decoration: underline; }\n");
    htmlprintf("table { border-collapse: collapse; }\n");
    htmlprintf("th,td { text-align: left; }\n");
    htmlprintf("th { padding: 0.1em 0.4em; border: none;"
               " font-size: smaller; font-weight: normal; }\n");
    htmlprintf("td { padding: 0.2em 0.5em; background-color: #ddddee;"
               " border: 1pt solid #888888; }\n");
    htmlprintf(".note { margin: 0.5em 0.5em; text-align: right; }\n");
    htmlprintf("</style>\n");
    htmlprintf("</head>\n");
    htmlprintf("<body>\n");
    htmlprintf("<h1>%@</h1>\n", Login);
    htmlprintf("<hr />\n");
    htmlprintf("<form method=\"post\" action=\"%s?mode=login\">\n",
               scriptname);
    htmlprintf("<div>\n");
    htmlprintf("<input type=\"text\" name=\"id\" size=\"32\" />\n");
    htmlprintf("<input type=\"password\" name=\"pass\" size=\"32\" />\n");
    htmlprintf("<input type=\"submit\" value=\"LOGIN\" tabindex=\"2\" accesskey=\"1\" />\n");
    htmlprintf("</div>\n");
    htmlprintf("</form>\n");
    htmlprintf("<hr />\n");


    /* output footers */
    htmlprintf("<div class=\"note\">Powered by QDBM %@.</div>\n", dpversion);
    htmlprintf("</body>\n");
    htmlprintf("</html>\n");



}

void disp_chpass(char *Login)
{
    printf("Content-Type: text/html; charset=%s\r\n", enc);
    printf("Cache-Control: no-cache, must-revalidate\r\n");
    printf("Pragma: no-cache\r\n");
    printf("\r\n");
    htmlprintf("<?xml version=\"1.0\" encoding=\"%s\"?>\n", enc);
    htmlprintf("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" "
               "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n");
    htmlprintf("<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"%s\" lang=\"%s\">\n",
               lang, lang);
    htmlprintf("<head>\n");
    htmlprintf("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\" />\n", enc);
    htmlprintf("<meta http-equiv=\"Content-Style-Type\" content=\"text/css\" />\n");
    htmlprintf("<link rel=\"contents\" href=\"./\" />\n");
    htmlprintf("<title>%@</title>\n", Login);
    htmlprintf("<style type=\"text/css\">\n");
    htmlprintf("body { background-color: #eeeeee; color: #111111;"
               " margin: 1em 1em; padding: 1em 1em; }\n");
    htmlprintf("hr { margin: 1.5em 0em; height: 1pt;"
               " color: #999999; background-color: #999999; border: none; }\n");
    htmlprintf("a { color: #0022aa; text-decoration: none; }\n");
    htmlprintf("a:hover { color: #1144ff; text-decoration: underline; }\n");
    htmlprintf("table { border-collapse: collapse; }\n");
    htmlprintf("th,td { text-align: left; }\n");
    htmlprintf("th { padding: 0.1em 0.4em; border: none;"
               " font-size: smaller; font-weight: normal; }\n");
    htmlprintf("td { padding: 0.2em 0.5em; background-color: #ddddee;"
               " border: 1pt solid #888888; }\n");
    htmlprintf(".note { margin: 0.5em 0.5em; text-align: right; }\n");
    htmlprintf("</style>\n");
    htmlprintf("</head>\n");
    htmlprintf("<body>\n");
    htmlprintf("<h1>%@</h1>\n", Login);
    htmlprintf("<hr />\n");
    htmlprintf("<form method=\"post\" action=\"%s?mode=chpass\">\n",
               scriptname);
    htmlprintf("<div>\n");
    htmlprintf("Old Pass<input type=\"password\" name=\"oldpass\" size=\"16\" />\n");
    htmlprintf("New Pass<input type=\"password\" name=\"newpass1\" size=\"16\" />\n");
    htmlprintf("New Pass<input type=\"password\" name=\"newpass2\" size=\"16\" />\n");
    htmlprintf("<input type=\"submit\" value=\"CHANGEPASSWORD\" tabindex=\"5\" accesskey=\"1\" />\n");
    htmlprintf("</div>\n");
    htmlprintf("</form>\n");
    htmlprintf("<hr />\n");


    /* output footers */
    htmlprintf("<div class=\"note\">Powered by QDBM %@.</div>\n", dpversion);
    htmlprintf("</body>\n");
    htmlprintf("</html>\n");
}
/* END OF FILE */

