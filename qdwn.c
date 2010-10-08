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
int checkcandownload(char *hash);
CBLIST *gethash2filename(char *hash);


void disp();
void self_redirect(int sec,char *message,char *myself,char *enc);

/* main routine */
int main(int argc, char **argv){
  CBLIST *lines, *fileinfo;
  CBMAP *params;
  FILE *ifp;
  const char *tmp, *datadir,*ses;
  char *filedata, *filename, *getname, *delname;
  char *filehash,*userid;
  int i, clen, filesize,ret;
  char *id,*pass;
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

  params = getparams();
  if((tmp = cbmapget(params, "hash", -1, NULL)) != NULL) filehash = (char *)tmp;

  if(filehash){
    /* send data of the file */
    if (chdir(datadir)==0) {
      fileinfo = gethash2filename(filehash);
      if (fileinfo) {
        getname = cblistval(fileinfo,0,NULL);
      }
    }
    ret = checkcandownload(filehash);
    if (ret != TRUE) {
      char *msg;
      msg = cbsprintf("Download Check Error code %d",ret);
      self_redirect(30,msg,scriptname,enc);
      cbfree(msg);
      return 0;
    }

    ifp = fopen(getname,"rb");
    if(ifp != NULL){
      char *rbuf;
      printf("Content-Disposition: attachment; filename=\"%s\"\r\n",getname);
      printf("Content-Type: %s\r\n", "application/octet-stream");
      printf("Cache-Control: no-cache, must-revalidate\r\n");
      printf("Pragma: no-cache\r\n");
      printf("\r\n");
      rbuf = cbmalloc(RDATAMAX);
      while(1) {
        clen = fread(rbuf,1,RDATAMAX,ifp);
        fwrite(rbuf,1,clen,stdout);
        if (feof(ifp)) break;
      }
      cbfree(rbuf);
      fclose(ifp);
    } else {
      printf("Content-Type: text/html; charset=%s\r\n", enc);
      printf("Cache-Control: no-cache, must-revalidate\r\n");
      printf("\r\n");

      htmlprintf("<META HTTP-EQUIV=\"Refresh\" CONTENT=\"10; URL=%s\">\r\n",scriptname);
      htmlprintf("<h1> Invalid Key OR File Not Found</h1>\r\n");
    }
  } else {
    disp();
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

void disp()
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
    htmlprintf("<title>%@</title>\n", "Download");
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
    htmlprintf("<h1>%@</h1>\n", "Download");
    htmlprintf("<hr />\n");
    htmlprintf("<form method=\"post\" action=\"%s\">\n",
               scriptname);
    htmlprintf("<div>\n");
    htmlprintf("<input type=\"text\" name=\"hash\" size=\"64\" />\n");
    htmlprintf("<input type=\"submit\" value=\"GET\" tabindex=\"2\" accesskey=\"1\" />\n");
    htmlprintf("</div>\n");
    htmlprintf("</form>\n");
    htmlprintf("<hr />\n");


    /* output footers */
    htmlprintf("<div class=\"note\">Powered by QDBM %@.</div>\n", dpversion);
    htmlprintf("</body>\n");
    htmlprintf("</html>\n");
}
/* END OF FILE */

