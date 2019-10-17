package whois

// http://www.iana.org/domains/root/db/
// Two tab separated entries per line: TLD   WHOIS-SERVER
// First match is served

var tldServerList = string(`

.br.com	whois.centralnic.net
.cn.com	whois.centralnic.net
.de.com	whois.centralnic.net
.eu.com	whois.centralnic.net
.gb.com	whois.centralnic.net
.gb.net	whois.centralnic.net
.gr.com	whois.centralnic.net
.hu.com	whois.centralnic.net
.in.net	whois.centralnic.net
.no.com	whois.centralnic.net
.qc.com	whois.centralnic.net
.ru.com	whois.centralnic.net
.sa.com	whois.centralnic.net
.se.com	whois.centralnic.net
.se.net	whois.centralnic.net
.uk.com	whois.centralnic.net
.uk.net	whois.centralnic.net
.us.com	whois.centralnic.net
.uy.com	whois.centralnic.net
.za.com	whois.centralnic.net
.jpn.com	whois.centralnic.net
.web.com	whois.centralnic.net

.eu.org	whois.eu.org
.za.org	whois.za.org
.za.net	whois.za.net

.com	whois.verisign-grs.com
.net	whois.verisign-grs.com
.org	whois.pir.org

.edu	whois.educause.edu
.gov	whois.dotgov.gov
.int	whois.iana.org

.aero	whois.aero
.asia	whois.nic.asia
.biz	whois.nic.biz
.cat	whois.nic.cat
.coop	whois.nic.coop
.info	whois.afilias.net
.jobs	whois.nic.jobs
.mobi	whois.afilias.net
.museum	whois.nic.museum
.name	whois.nic.name
.post	whois.dotpostregistry.net
.pro	whois.afilias.net
.tel	whois.nic.tel
.today	whois.nic.today
.travel	whois.nic.travel
.xxx	whois.nic.xxx

.ac	whois.nic.ac
.ae	whois.aeda.net.ae
.af	whois.nic.af
.ag	whois.nic.ag
.ai	whois.nic.ai
.am	whois.amnic.net
.ar	whois.nic.ar
.as	whois.nic.as
.at	whois.nic.at
.au	whois.auda.org.au
.aw	whois.nic.aw
.ax	whois.ax

.be	whois.dns.be
.bg	whois.register.bg
.bi	whois1.nic.bi
.bj	whois.nic.bj
.bm	whois.afilias-srs.net
.bn	whois.bnnic.bn
.bo	whois.nic.bo
.br	whois.registro.br
.by	whois.cctld.by
.bw	whois.nic.net.bw

.co.ca	whois.co.ca
.ca	whois.cira.ca
.cc	ccwhois.verisign-grs.com
.cd	whois.nic.cd
.cf	whois.dot.cf
.ci	whois.nic.ci
.cl	whois.nic.cl
.cm	whois.netcom.cm
.edu.cn	whois.edu.cn
.cn	whois.cnnic.cn
.uk.co	whois.uk.co
.co	whois.nic.co
.cr	whois.nic.cr
.cx	whois.nic.cx
.cz	whois.nic.cz

.de	whois.denic.de
.dk	whois.dk-hostmaster.dk
.dm	whois.nic.dm
.do	whois.nic.do
.dz	whois.nic.dz

.ec	whois.nic.ec
.ee	whois.tld.ee
.es	whois.nic.es
.eu	whois.eu

.fi	whois.fi
.fj	whois.usp.ac.fj
.fm	whois.nic.fm
.fo	whois.nic.fo
.fr	whois.nic.fr

.ga	whois.dot.ga
.gd	whois.nic.gd
.ge	whois.nic.ge
.gf	whois.mediaserv.net
.gg	whois.gg
.gh	whois.nic.gh
.gi	whois2.afilias-grs.net
.gl	whois.nic.gl
.gp	whois.nic.gp
.gq	whois.dominio.gq
.gs	whois.nic.gs
.gy	whois.registry.gy

.hk	whois.hkirc.hk
.hm	whois.registry.hm
.hn	whois.nic.hn
.hr	whois.dns.hr
.ht	whois.nic.ht
.hu	whois.nic.hu

.id	whois.id
.ie	whois.iedr.ie
.il	whois.isoc.org.il
.im	whois.nic.im
.in	whois.registry.in
.io	whois.nic.io
.iq	whois.cmc.iq
.ir	whois.nic.ir
.is	whois.isnic.is
.it	whois.nic.it

.je	whois.je
.jp	whois.jprs.jp

.ke	whois.kenic.or.ke
.kg	whois.kg
.ki	whois.nic.ki
.kn	whois.nic.kn
.kr	whois.kr
.kw	whois.nic.kw
.ky	whois.kyregistry.ky
.kz	whois.nic.kz

.la	whois.nic.la
.lc	whois2.afilias-grs.net
.li	whois.nic.li
.lk	whois.nic.lk
.ls	whois.nic.ls
.lt	whois.domreg.lt
.lu	whois.dns.lu
.lv	whois.nic.lv
.ly	whois.nic.ly

.ma	whois.registre.ma
.md	whois.nic.md
.me	whois.nic.me
.mg	whois.nic.mg
.mk	whois.marnet.mk
.ml	whois.dot.ml
.mn	whois.nic.mn
.mq	whois.mediaserv.net
.mr	whois.nic.mr
.ms	whois.nic.ms
.mu	whois.nic.mu
.mw	whois.nic.mw
.mx	whois.mx
.my	whois.mynic.my
.mz	whois.nic.mz

.na	whois.na-nic.com.na
.nc	whois.nc
.nf	whois.nic.nf
.ng	whois.nic.net.ng
.nl	whois.domain-registry.nl
.no	whois.norid.no
.nu	whois.iis.nu
.nz	whois.srs.net.nz

.om	whois.registry.om

.pe	kero.yachay.pe
.pf	whois.registry.pf
.pl	whois.dns.pl
.pm	whois.nic.pm
.pr	whois.afilias-srs.net
.ps	whois.pnina.ps
.pt	whois.dns.pt
.pw	whois.nic.pw
.qa	whois.registry.qa

.re	whois.nic.re
.ro	whois.rotld.ro
.rs	whois.rnids.rs

.edu.ru	whois.informika.ru
.ru	whois.tcinet.ru
.rw	whois.ricta.org.rw

.sa	whois.nic.net.sa
.sb	whois.nic.net.sb
.sc	whois2.afilias-grs.net
.se	whois.iis.se
.sg	whois.sgnic.sg
.sh	whois.nic.sh
.si	whois.register.si
.sk	whois.sk-nic.sk
.sl	whois.nic.sl
.sm	whois.nic.sm
.sn	whois.nic.sn
.so	whois.nic.so
.ss	whois.nic.ss
.st	whois.nic.st
.su	whois.tcinet.ru
.sx	whois.sx
.sy	whois.tld.sy

.tc	whois.nic.tc
.td	whois.nic.td
.tf	whois.nic.tf
.tg	whois.nic.tg
.th	whois.thnic.co.th
.tk	whois.dot.tk
.tl	whois.nic.tl
.tm	whois.nic.tm
.tn	whois.ati.tn
.to	whois.tonic.to
.tr	whois.nic.tr
.tv	tvwhois.verisign-grs.com
.tw	whois.twnic.net.tw
.tz	whois.tznic.or.tz

.biz.ua	whois.biz.ua
.co.ua	whois.co.ua
.pp.ua	whois.pp.ua
.ua	whois.ua
.ug	whois.co.ug
.ac.uk	whois.ja.net
.gov.uk	whois.ja.net
.co.uk	whois.nic.uk
.uk	whois.nic.uk
.fed.us	whois.nic.gov
.us	whois.nic.us
.uy	whois.nic.org.uy
.uz	whois.cctld.uz
.vc	whois2.afilias-grs.net
.ve	whois.nic.ve
.vg	whois.nic.vg
.vu	vunic.vu
.wf	whois.nic.wf
.ws	whois.website.ws
.yt	whois.nic.yt
.ac.za	whois.ac.za
.alt.za	whois.alt.za
.co.za	whois.registry.net.za
.gov.za	whois.gov.za
.net.za	net-whois.registry.net.za
.org.za	org-whois.registry.net.za
.web.za	web-whois.registry.net.za
.zm	whois.zicta.zm
`)
