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
#include <sys/time.h>
#include <unistd.h>
#include <md5.h>
#include <sha.h>

#undef TRUE
#define TRUE           1                 /* boolean true */
#undef FALSE
#define FALSE          0                 /* boolean false */

#define RDATAMAX    67108864             /* max size of data to read */

extern const char *scriptname;
extern const char *enc;

void htmlprintf(const char *format, ...);

time_t getlocaltimenow();

/* get a map of the CGI parameters */
CBMAP *getparams(void){
  CBMAP *params;
  CBLIST *pairs;
  char *rbuf, *buf, *key, *val, *dkey, *dval;
  const char *tmp;
  int i, len, c;
  params = cbmapopen();
  rbuf = NULL;
  buf = NULL;
  if((tmp = getenv("CONTENT_LENGTH")) != NULL && (len = atoi(tmp)) > 0 && len <= RDATAMAX){
    rbuf = cbmalloc(len + 1);
    for(i = 0; i < len && (c = getchar()) != EOF; i++){
      rbuf[i] = c;
    }
    rbuf[i] = '\0';
    if(i == len) buf = rbuf;
  } else {
    buf = getenv("QUERY_STRING");
  }
  if(buf != NULL){
    buf = cbmemdup(buf, -1);
    pairs = cbsplit(buf, -1, "&");
    for(i = 0; i < cblistnum(pairs); i++){
      key = cbmemdup(cblistval(pairs, i, NULL), -1);
      if((val = strchr(key, '=')) != NULL){
        *(val++) = '\0';
        dkey = cburldecode(key, NULL);
        dval = cburldecode(val, NULL);
        cbmapput(params, dkey, -1, dval, -1, FALSE);
        free(dval);
        free(dkey);
      }
      free(key);
    }
    cblistclose(pairs);
    free(buf);
  }
  free(rbuf);
  return params;
}

void self_redirect(int sec,char *msg,char *myself,char *enc)
{
      printf("Content-Type: text/html; charset=%s\r\n", enc);
      printf("Cache-Control: no-cache, must-revalidate\r\n");
      printf("\r\n");

      if (sec > 0) {
        htmlprintf("<META HTTP-EQUIV=\"Refresh\" CONTENT=\"%d; URL=%s\">\r\n",sec,myself);
      }
      if (msg) {
            htmlprintf("<h1>%@</h1>\n", msg);
            htmlprintf("<BR>  <a href=\"%s\">Back</a>\n", myself);
      }
}


/* get a map of the cookie */
CBMAP *getcookie(void){
  CBMAP *params;
  CBLIST *pairs;
  char *rbuf, *buf, *key, *val, *dkey, *dval;
  int i;
  params = cbmapopen();
  rbuf = NULL;
  buf = NULL;
  buf = getenv("HTTP_COOKIE");
  if(buf != NULL){
    buf = cbmemdup(buf, -1);
    pairs = cbsplit(buf, -1, ";");
    for(i = 0; i < cblistnum(pairs); i++){
      key = cbmemdup(cblistval(pairs, i, NULL), -1);
      if((val = strchr(key, '=')) != NULL){
        *(val++) = '\0';
        dkey = cburldecode(key, NULL);
        dval = cburldecode(val, NULL);
        cbmapput(params, dkey, -1, dval, -1, FALSE);
        free(dval);
        free(dkey);
      }
      free(key);
    }
    cblistclose(pairs);
    free(buf);
  }
  else {
    return NULL;
  }
  return params;
}


/* get a string for PATH_INFO */
char *getpathinfo(void){
  const char *tmp;
  if((tmp = getenv("PATH_INFO")) != NULL){
    return cburldecode(tmp, NULL);
  }
  return NULL;
}


/* HTML-oriented printf */
void htmlprintf(const char *format, ...){
  va_list ap;
  char *tmp;
  unsigned char c;
  va_start(ap, format);
  while(*format != '\0'){
    if(*format == '%'){
      format++;
      switch(*format){
      case 's':
        tmp = va_arg(ap, char *);
        if(!tmp) tmp = "(null)";
        printf("%s", tmp);
        break;
      case 'd':
        printf("%d", va_arg(ap, int));
        break;
      case '@':
        tmp = va_arg(ap, char *);
        if(!tmp) tmp = "(null)";
        while(*tmp){
          switch(*tmp){
          case '&': printf("&amp;"); break;
          case '<': printf("&lt;"); break;
          case '>': printf("&gt;"); break;
          case '"': printf("&quot;"); break;
          default: putchar(*tmp); break;
          }
          tmp++;
        }
        break;
      case '?':
        tmp = va_arg(ap, char *);
        if(!tmp) tmp = "(null)";
        while(*tmp){
          c = *(unsigned char *)tmp;
          if((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
             (c >= '0' && c <= '9') || (c != '\0' && strchr("_-.", c))){
            putchar(c);
          } else if(c == ' '){
            putchar('+');
          } else {
            printf("%%%02X", c);
          }
          tmp++;
        }
        break;
      case '%':
        putchar('%');
        break;
      }
    } else {
      putchar(*format);
    }
    format++;
  }
  va_end(ap);
}

static char *days[] = {
        "Sun",
        "Mon",
        "Tue",
        "Wed",
        "Thu",
        "Fri",
        "Sat"
};

static char *months[] = {
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec"
};


void setcookie(char *name,char *value,char *domain,int kigen,char *path)
{
        time_t now;
	time_t then;
	char *str;
        time(&now);
        then = now + kigen;
	str = cbdatestrhttp(then,0);
	printf("Set-Cookie: %s=%s; expires=%s;\r\n",name,value,str);
	free(str);
/*
        printf(
                "Set-Cookie: %s=%s; domain=%s; expires=%s, %02d-%s-%04d %02d:%02d:%02d GMT; path=%s\r\n",
                name, value, domain,
                days[gt->tm_wday],
                gt->tm_mday,
                months[gt->tm_mon],
                gt->tm_year + 1900,
                gt->tm_hour,
                gt->tm_min,
                gt->tm_sec,
                path);
*/

}

/* send error status */
void senderror(int code, const char *tag, const char *message){
  printf("Status: %d %s\r\n", code, tag);
  printf("Content-Type: text/plain; charset=US-ASCII\r\n");
  printf("\r\n");
  printf("%s\n", message);
}

char *getsha1file(char *input)
{
  return SHA1_File(input,NULL);
}
char *getmd5str(char *input)
{
    MD5_CTX md5;
    unsigned char *digest;
    char *outid=NULL;
    int i;
    MD5Init(&md5);   
    MD5Update(&md5,input,strlen(input));
    digest = cbmalloc(17);
    MD5Final(digest,&md5);
    outid=cbmalloc(33);
    for(i=0;i<16;i++) {
     sprintf(outid + (i*2),"%02X",digest[i]);
    }
    free(digest);
    return outid;
}

char  *getsessionid()
{
     char *buf, *tmp,*outid;
     struct timeval tv;
     char *remote_addr = NULL;
     pid_t pid;

     gettimeofday(&tv, NULL);
     pid = getpid();
     /* remote */
     if((tmp = getenv("REMOTE_ADDR")) != NULL){
       remote_addr = tmp;
     }

     /* maximum 15+19+19+10 bytes */
    buf = cbmalloc(15+19+19+10+1);
    sprintf(buf, "%.15s%ld%ld%d", remote_addr ? remote_addr : "", tv.tv_sec, (long int)tv.tv_usec, pid);
    outid = getmd5str(buf);

   return outid;
}


#define SESSION_DBFILE	".sessiondb.dp"

void cleansession(char *sessiondb,char *sessionid,char *userid)
{
  DEPOT *depot;
  CBLIST *list;
  char *kbuf, *vbuf;
  int ksiz, vsiz;
  if(!(depot = dpopen(sessiondb, DP_OWRITER, -1))){
    return;
  }
  dpiterinit(depot);
  while((kbuf = dpiternext(depot, &ksiz)) != NULL){
    if(!(vbuf = dpget(depot, kbuf, ksiz, 0, -1, &vsiz))){
      free(kbuf);
      break;
    }
   list = cbsplit(vbuf,-1,","); 
   /*  DB内容によって処理。（同一ユーザーは認めない・１ヶ月たったら削除など */
   cblistclose(list);
   free(kbuf);
   free(vbuf);
  }
  dpclose(depot);
}

int removesession(char *sessionid,char *datadir)
{
  DEPOT *depot;
  char *sessiondb;

  sessiondb = cbsprintf("%s/%s",datadir,SESSION_DBFILE);
  
  if(!(depot = dpopen(sessiondb, DP_OWRITER, -1))){
    free(sessiondb);
    return FALSE;
  }
  dpout(depot,sessionid,-1);
  dpclose(depot);
  free(sessiondb);
  return TRUE;
}

int createsession(char *id,char *sessionid,char *datadir)
{
  char *vbuf;
  char *datestr;
   char *remote_addr = NULL;
   char *tmp;
   DEPOT *depot;
   char *sessiondb;

   sessiondb = cbsprintf("%s/%s",datadir,SESSION_DBFILE);
  
   if (cbfilestat(sessiondb,NULL,NULL,NULL)==FALSE) {
    if(!(depot = dpopen(sessiondb, DP_OWRITER | DP_OCREAT | DP_OTRUNC, -1)) ||
       !dpclose(depot)) {
       senderror(404, "DB Create Error", "DB Create Error.");
       return FALSE;
    }
   }
   if(!(depot = dpopen(sessiondb, DP_OWRITER, -1))){
    senderror(404, "DB Open Error", "DB Open Error For Write .sessiondb.dp.");
    return FALSE;
  }
  datestr = cbdatestrwww(-1,cbjetlag());
  /* remote */
  if((tmp = getenv("REMOTE_ADDR")) != NULL){
    remote_addr = tmp;
  }
  vbuf=cbsprintf("%s,%s,%s",id,datestr,remote_addr ? remote_addr : "");
  free(datestr);
  if(dpput(depot, sessionid, -1, vbuf, -1, DP_DOVER)==FALSE){
    senderror(500, "DB Write Error", "DB Write Error .sessiondb.dp.");
    dpclose(depot);
    return FALSE;
  }
  dpclose(depot);
  free(vbuf);
  free(sessiondb);
  return TRUE;
}

char  *chksession(char *id,char *datadir)
{
 CBLIST *pairs;
 char *retid;
 char *vbuf;
 int vsiz;
 DEPOT *depot;
 char *sessiondb;
 sessiondb  = cbsprintf("%s/%s",datadir,SESSION_DBFILE);
 if((depot = dpopen(sessiondb, DP_OREADER, -1)) != NULL){
    vbuf = dpget(depot, id, -1, 0, -1, &vsiz);
    dpclose(depot);
    if (vbuf==NULL) {
      return NULL;
    }
    pairs = cbsplit(vbuf,-1,",");
    retid = cbmemdup(cblistval(pairs, 0, NULL), -1);   
    cblistclose(pairs);
    free(sessiondb);
    return retid;
  }
  free(sessiondb);
  return NULL;
}


#define USER_DBFILE	".userdb.dp"
#define	PPHASHSTR	"quplhash_"

CBLIST *chkuser(char *id,char *pass,char *datadir)
{
   DEPOT *depot;
   char  *userdb;
   char  *vbuf;
   char  *ps,*hash;
   int   vsiz;
  CBLIST *pairs;

   userdb = cbsprintf("%s/%s",datadir,USER_DBFILE);
  
   if (cbfilestat(userdb,NULL,NULL,NULL)==FALSE) {
    if(!(depot = dpopen(userdb, DP_OWRITER | DP_OCREAT | DP_OTRUNC, -1)) ||
       !dpclose(depot)) {
       senderror(404, "DB Create Error", "DB Create Error UserDB.");
       return NULL;
    }
     /* 最初の管理ユーザ作成*/
     if(!(depot = dpopen(userdb, DP_OWRITER, -1))){
      senderror(404, "DB Open Error", "DB Open Error For Write .userdb.dp.");
      return NULL;
     }
     ps = cbsprintf("%s%s","root",PPHASHSTR);
     hash = getmd5str(ps);
     vbuf = cbsprintf("%s,1,%s",hash,"admin");
     free(ps);
     free(hash);
     if(dpput(depot, "administrator", -1, vbuf, -1, DP_DOVER)==FALSE){
      senderror(404, "DB Open Error", "DB Write Error administrator .userdb.dp.");
      return NULL;
     }
     dpclose(depot);
     free(vbuf);
   }
   if((depot = dpopen(userdb, DP_OREADER, -1)) != NULL){
    vbuf = dpget(depot, id, -1, 0, -1, &vsiz);
    dpclose(depot);
    if (vbuf==NULL) {
      return NULL;
    }
    pairs = cbsplit(vbuf,-1,",");
    free(userdb);
    ps = cbsprintf("%s%s",pass,PPHASHSTR);
    hash = getmd5str(ps);
    if (strcmp(hash,cblistval(pairs,0,NULL))==0) {
      free(ps);
      return pairs;
    }
    free(ps);
    free(vbuf);
    cblistclose(pairs);
    return NULL;
   }
   return NULL;
}
CBLIST *getuser(char *id,char *datadir)
{
   DEPOT *depot;
   char  *userdb;
   char  *vbuf;
   char  *ps,*hash;
   int   vsiz;
   CBLIST *pairs;

   userdb = cbsprintf("%s/%s",datadir,USER_DBFILE);

   if((depot = dpopen(userdb, DP_OREADER, -1)) != NULL){
    vbuf = dpget(depot, id, -1, 0, -1, &vsiz);
    dpclose(depot);
    if (vbuf==NULL) {
      return NULL;
     }
     pairs = cbsplit(vbuf,-1,",");
     free(userdb);
     free(vbuf);

     return pairs;
   }
   return NULL;
}

/* .tmp で始まるファイルで２４時間経過後のファイルを削除 */
void chktmp(char *dir)
{
     CBLIST *files;
     char *sname,*rname;
     size_t ssize;
     time_t stime;
     time_t ntime;
     int i,sdir;
     ntime = getlocaltimenow();
      if((files = cbdirlist(dir)) != NULL){
        cblistsort(files);
        for(i = 0; i < cblistnum(files); i++){
          sname = (char *)cblistval(files, i, NULL);
          if((!(strcmp(sname, "."))&&strlen(sname)==1) || !strcmp(sname, "..")) continue;
          if (!cbstrfwmatch(sname,".tmp")) continue;
          rname = cbsprintf("%s/%s",dir,sname);
          if(!cbfilestat(rname, &sdir, (int *)&ssize, (int *)&stime) || sdir) continue;
          if (stime + 86400 < ntime) {
            unlink(rname);
          }
          free(rname);
          
        }
      }
      cblistclose(files);
}
/* get static string of the date */
const char *datestr(time_t t){
  static char buf[32];
  struct tm *stp;
  if(!(stp = localtime(&t))) return "0000/00/00 00:00:00";
  sprintf(buf, "%04d/%02d/%02d %02d:%02d:%02d",
          stp->tm_year + 1900, stp->tm_mon + 1, stp->tm_mday,
          stp->tm_hour, stp->tm_min, stp->tm_sec);
  return buf;
}


time_t getlocaltimenow()
{
  time_t t;
  if((t = time(NULL)) < 0) return 0;
  t = t + cbjetlag();
  return t;
}

char *maketmpfname(dir,no)
  char *dir;
  int no;
{
  pid_t pid;
  pid = getpid();
  if (dir)
    return cbsprintf("%s/.tmp_%d_%d",dir,pid,no);
  else
    return cbsprintf(".tmp_%d_%d",pid,no);
}


char * makeuploadtmpfile(char *dir, int no)
{
   FILE *ifp;
   FILE *ofp;

   char *rbuf,*ofname;
   size_t rlen,wlen;

   rbuf = cbmalloc(RDATAMAX+1);
   ofname = maketmpfname(dir,no);

   if (rbuf == NULL || ofname == NULL) return NULL;

   ifp = stdin;
   ofp = fopen(ofname,"wb");
   
   if (ofp==NULL) {
     return NULL;
   }
   while(1) {
     rlen = fread(rbuf,1,RDATAMAX,ifp);
     wlen = fwrite(rbuf,1,rlen,ofp);
     if (feof(ifp)) break;
   }
   fclose(ofp);

   free(rbuf);
   return ofname;
}


static int removezerotmp(char *dir,int no)
{
  char *fname;
  int size;
  fname = maketmpfname(dir,no);
  if (cbfilestat(fname,NULL,&size,NULL)) {
    if (size==0) {unlink(fname); return 1;} 
  }
  return 0;
}
static void createtmp(char *dir,int no)
{
  char *fname;
  FILE *fp;

  fname = maketmpfname(dir,no);
  fp = fopen(fname,"wb");
  if (fp) fclose(fp);
  free(fname);
}
static void appendtmp(char *dir,int start,char *buf,int len,int blen)
{
      int ret;
      char *fname;
      FILE *fp;
      if (len-blen<0) return;
      fname = maketmpfname(dir,start);
      fp = fopen(fname,"a");
      ret = fwrite(buf,len-blen,1,fp);
      fclose(fp);
      free(fname);
}

/* uplodファイルをboudaryで分割 */
int splituploadtmp(char *bound,char *dir,char *fname)
{
    char *rbuf,*ptr;
    const char *pv, *ep;
    int blen,rlen,i,start;
    int   fixbound;
    FILE *fp;
    blen = strlen(bound);
    fp = fopen(fname,"rb");
    if (fp==NULL) {return 0;}

    rbuf = cbmalloc(RDATAMAX);
    start=0;
    while(1) {
      memset(rbuf,0,RDATAMAX);
      rlen = fread(rbuf,1,RDATAMAX,fp);
      ptr = NULL;
      fixbound=0;
      
      if (start==0) { /* 開始位置検索 */
       for(ptr = rbuf,i = 0; i < rlen; i++){
        if(ptr[i] == '-' && ptr[i+1] == '-' && i + 2 + blen < rlen &&
         cbstrfwmatch(ptr + i + 2, bound) && strchr("\t\n\v\f\r ", ptr[i+2+blen])){
           pv = ptr + i + 2 + blen;
           if(*pv == '\r') pv++;
           if(*pv == '\n') pv++;
           ptr = (char *)pv;
           start=1;
           createtmp(dir,start);
           break;
        }
       }
      }
      if (start>0) { /* 終了位置検索 */
        /* 読み込みバッファの最初からか、検索開始位置かどちらか */
        if (ptr==NULL) {
          pv = ptr = rbuf;
        }
        else {
          rlen = rlen - (pv - rbuf);
        }
        for(i = 0; i < rlen; i++){
          if(ptr[i] == '-' && ptr[i+1] == '-' && i + 2 + blen < rlen &&
             cbstrfwmatch(ptr + i + 2, bound) && strchr("\t\n\v\f\r -", ptr[i+2+blen])){
            ep = ptr + i;
            if(ep > ptr && ep[-1] == '\n') ep--;
            if(ep > ptr && ep[-1] == '\r') ep--;
            if(ep > pv) { 
              appendtmp(dir,start,(char *)pv,ep-pv,0);
              /* 次のboundryを発見した=ここまでがひとかたまり */
              start++;
              createtmp(dir,start);
              fixbound=1;
            }
            /*次の開始位置セット*/
            pv = ptr + i + 2 + blen;
            if(*pv == '\r') pv++;
            if(*pv == '\n') pv++;
          }
        }
      }
      /* 一時ファイルに追記 */
      if (ptr==NULL) ptr = rbuf;
      else {
        if (fixbound) {ptr = pv;rlen = rlen - (pv - rbuf);}
      }
      appendtmp(dir,start,ptr,rlen,blen);


      if (feof(fp)) {
        break;
      }
      /* バウンダリ分戻る */
      fseek(fp,(blen)*-1,SEEK_CUR);
    }
   fclose(fp);
   /* 0tmpができることがあるので消す */
   if (removezerotmp(dir,start)) start--;
   
   cbfree(rbuf);
   return start;
}


/* boundary 分割済みのcontentファイルを実ファイルとして保存 */
char *gettmptoreal(char *dir,char *infname,char **outfname)
{
  char *rbuf,*filename,*tmp;
  FILE *ifp,*ofp;
  int  rlen,wlen,filesize,skiplen;
  char *filedata,*ofname,*encname;
  CBMAP *params;
  char  *sha1hash;

  ifp = fopen(infname,"rb");
  if (ifp==NULL) return NULL;

  rbuf = cbmalloc(RDATAMAX);
  rlen = fread(rbuf,1,RDATAMAX,ifp);
  rewind(ifp);
  
  /* アップロード情報のファイル名を取得 */
  filename = filedata = NULL;
  params = cbmapopen();
  filedata = cbmimebreak(rbuf, rlen, params, &filesize);
  if((tmp = cbmapget(params, "FILENAME", -1, NULL)) != NULL) filename = cbmemdup(tmp, -1);
  cbmapclose(params);

  if (filedata) free(filedata);
 
  /* mime区切りまでの長さを取得 */
  tmp = strstr(rbuf,"\r\n\r\n");
  if (tmp) {
    skiplen = tmp - rbuf;
    skiplen = skiplen + 4; /* \r\n\r\n分 */
  } 

  /* ファイル名がない場合はアップロードファイルではない */
  if (filename ==NULL || tmp == NULL) {
    free(rbuf);
    fclose(ifp);
    return NULL;
  }
  /* パスチェック */
  if(cbstrfwmatch(filename, "../") || strstr(filename, "/../") != NULL){
    free(rbuf);
    fclose(ifp);
    return NULL;
  }

  
  /* ファイル名はURLEncodeしておく */
  encname = cburlencode(filename,-1);
  ofname = cbsprintf("%s/%s",dir,encname);
  *outfname = filename;
  ofp = fopen(ofname,"wb");
  if (ofp == NULL) {
    free(rbuf);
    free(ofname);
    free(encname);
    return NULL;
  }
  fseek(ifp,skiplen,SEEK_CUR);
  while(1) {
    rlen = fread(rbuf,1,RDATAMAX,ifp);
    wlen = fwrite(rbuf,1,rlen,ofp);
    if (feof(ifp)) break;
  }
  fclose(ofp);
  fclose(ifp);
  free(encname);
  free(rbuf);
  free(ofname);
  /* SHA1 ハッシュ */ 
  sha1hash =  getsha1file(ofname);
  return sha1hash;
}

#define RIREKI_DBFILE	".rirekidb.dp"

static int createrirekidb(char *hash,char *data) 
{
  DEPOT *depot;
  struct timeval tv;
  char *kbuf;
  char *vbuf;
  int rnum;
  if(!(depot = dpopen(RIREKI_DBFILE, DP_OWRITER|DP_OCREAT, -1))){
   senderror(404, "DB Open Error", "DB Open Error For Write .rirekidb.dp.");
   return FALSE;
  }
  gettimeofday(&tv,NULL);
  vbuf = cbsprintf("%s,%s",hash,data);
  if(dpput(depot, &tv, sizeof(tv), vbuf, -1, DP_DOVER)==FALSE){
    senderror(500, "DB Write Error", "DB Write Error .rirekidb.dp.");
    dpclose(depot);
    cbfree(vbuf);
    return FALSE;
  }
  cbfree(vbuf);
  dpclose(depot);
  return TRUE;
}

#define FILE_DBFILE	".filedb.dp"

int checkcandownload(char *hash)
{
  DEPOT *depot;
  char *remote_addr = NULL;
  char *datestr, *vbuf, *tmp, *obuf;
  int  vsiz,ret,downloadtime;
  CBLIST *fileinfo;
  time_t downtime1,downtime2;

  datestr = cbdatestrwww(-1,cbjetlag());
  /* remote */
  if((tmp = getenv("REMOTE_ADDR")) != NULL){
    remote_addr = tmp;
  }

  if(!(depot = dpopen(FILE_DBFILE, DP_OWRITER, -1))){
   return -1;
  }
  vbuf = dpget(depot, hash, -1, 0, -1, &vsiz);
  if (vbuf) {
      fileinfo = cbsplit(vbuf,-1,",");
      if (cblistnum(fileinfo)>5) {
         /* すでにダウンロードされている場合はIPが同じかチェック */
        if (strcmp(remote_addr,cblistval(fileinfo,5,NULL))!=0) {
          cbfree(vbuf);
          cbfree(datestr);
          dpclose(depot);
          return -2;
        }
        /* 取得時刻が極端に近い場合はエラー */
        downtime1 = cbstrmktime(cblistval(fileinfo,6,NULL));
        downtime2 = cbstrmktime(datestr);
        /* 取得にかかる時間(1MBPSとする)よりも短い間隔しか空いていない場合エラー */ 
        /* 30秒　最低 */
        downloadtime = (atoi(cblistval(fileinfo,1,NULL)) / (1024*1024) ) + 30;
        if ((downtime2 - downtime1) < downloadtime) {
          cbfree(vbuf);
          cbfree(datestr);
          dpclose(depot);
          return -3;
        }
      }
       
      /* ダウンロードアドレス、時刻を保存 */
      obuf = cbsprintf("%s,%s,%s,%s,%s,%s,%s",
             cblistval(fileinfo,0,NULL), /* Filename */
             cblistval(fileinfo,1,NULL), /* Size */
             cblistval(fileinfo,2,NULL), /* Upload Date */
             cblistval(fileinfo,3,NULL), /* Upload ID */
             cblistval(fileinfo,4,NULL), /* Upload IP */
             remote_addr,datestr);
      ret = TRUE;
      if(dpput(depot, hash, -1, obuf, -1, DP_DOVER)==FALSE){
        ret = -4;
      }
      dpclose(depot);
      cbfree(datestr);
      cbfree(obuf);
      cbfree(vbuf);
      return ret;
  }
  dpclose(vbuf);
  cbfree(datestr);

  return 0;
}

int creatfiledb(char *datadir,char *hash,char *fname,char *updid)
{
  char *vbuf;
  char *datestr;
  char *remote_addr = NULL;
  char *tmp;
  DEPOT *depot;
  char *filedb;
  char *encfname;
  char *realfile;
  int  size;

  filedb = cbsprintf("%s/%s",datadir,FILE_DBFILE);
  
  if (cbfilestat(filedb,NULL,NULL,NULL)==FALSE) {
   if(!(depot = dpopen(filedb, DP_OWRITER | DP_OCREAT | DP_OTRUNC, -1)) ||
      !dpclose(depot)) {
      return -1;
   }
  }
  if(!(depot = dpopen(filedb, DP_OWRITER, -1))){
   return -2;
  }
  datestr = cbdatestrwww(-1,cbjetlag());
  /* remote */
  if((tmp = getenv("REMOTE_ADDR")) != NULL){
    remote_addr = tmp;
  }
  encfname = cburlencode(fname,-1);
  realfile = cbsprintf("%s/%s",datadir,encfname);
  if (cbfilestat(realfile,NULL,&size,NULL)==FALSE) {
    return -4;
  }
  
  vbuf=cbsprintf("%s,%d,%s,%s,%s",encfname,size,datestr,updid,remote_addr ? remote_addr : "");
  free(datestr);
  free(encfname);
  if(dpput(depot, hash, -1, vbuf, -1, DP_DOVER)==FALSE){
    dpclose(depot);
    return -3;
  }
  dpclose(depot);
  free(vbuf);
  free(filedb);
  free(realfile);
  free(encfname);
  return TRUE;
}


int isadmin(CBLIST *info,char *id)
{
   CBLIST *pairs;
   int adminflg;
   char *key;

   adminflg = FALSE;

   /* */
   key = cblistval(pairs, 1, NULL);
   if (strcmp(key,"1")==0) {
     adminflg=TRUE;
   }

   return adminflg;
}


/* キーハッシュからファイルとファイル情報を削除 */
/* 履歴DB作成 */
int removefilehash(char *hash)
{
 DEPOT *depot;
 char *vbuf;
 CBLIST *fileinfo;
 int  vsiz;
  if(!(depot = dpopen(FILE_DBFILE, DP_OWRITER, -1))){
    return FALSE;
  }
  vbuf = dpget(depot, hash, -1, 0, -1, &vsiz);
  if (vbuf) {
    /* 履歴DBを作成し、実ファイル削除 */
    if (createrirekidb(hash,vbuf)) {
      dpout(depot,hash,-1);
      fileinfo = cbsplit(vbuf,-1,",");
      unlink(cblistval(fileinfo,0,NULL));
    }
  }
  dpclose(depot);
  return TRUE;
}
/* キーハッシュからファイル情報取得 */
CBLIST *gethash2filename(char *hash)
{
  DEPOT *depot;
  CBLIST *rlist;
  char *kbuf, *vbuf,*tmp;
  int ksiz, vsiz;

  if(!(depot = dpopen(FILE_DBFILE, DP_OREADER, -1))){
    return NULL;
  }
  vbuf = dpget(depot, hash, -1, 0, -1, &vsiz);
  dpclose(depot);
  if (vbuf == NULL) {
    return NULL;
  }
  return cbsplit(vbuf,-1,",");
}
/* 自分のファイルをリストする */
CBLIST *listmyfiles(char *id)
{
  DEPOT *depot;
  CBLIST *list,*rlist;
  char *kbuf, *vbuf,*tmp;
  int ksiz, vsiz;
  if(!(depot = dpopen(FILE_DBFILE, DP_OREADER, -1))){
    return NULL;
  }
  rlist = NULL;
  dpiterinit(depot);
  while((kbuf = dpiternext(depot, &ksiz)) != NULL){
    if(!(vbuf = dpget(depot, kbuf, ksiz, 0, -1, &vsiz))){
      free(kbuf);
      break;
    }
    list = cbsplit(vbuf,-1,","); 
    if (strcmp(cblistval(list,3,NULL),id)==0) {
     if (rlist==NULL) {
       rlist = cblistopen();
     }
     tmp = cbsprintf("%s,%s",kbuf,vbuf); 
     cblistpush(rlist,tmp,-1);
    }
    cblistclose(list);
    free(kbuf);
    free(vbuf);
  }
  dpclose(depot);
  return rlist;
}
