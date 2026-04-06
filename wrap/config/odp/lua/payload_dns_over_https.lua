--[[
# Copyright 2001-2014 Cisco Systems, Inc. and/or its affiliates. All rights
# reserved.
#
# This file contains proprietary Detector Content created by Cisco Systems,
# Inc. or its affiliates ("Cisco") and is distributed under the GNU General
# Public License, v2 (the "GPL").  This file may also include Detector Content
# contributed by third parties. Third party contributors are identified in the
# "authors" file.  The Detector Content created by Cisco is owned by, and
# remains the property of, Cisco.  Detector Content from third party
# contributors is owned by, and remains the property of, such third parties and
# is distributed under the GPL.  The term "Detector Content" means specifically
# formulated patterns and logic to identify applications based on network
# traffic characteristics, comprised of instructions in source code or object
# code form (including the structure, sequence, organization, and syntax
# thereof), and all documentation related thereto that have been officially
# approved by Cisco.  Modifications are considered part of the Detector
# Content.
--]]
--[[
detection_name: DNS over HTTPS
version: 16
description: DNS traffic that is encrypted and obfuscated with HTTPS. DoH domains are extracted from an automated process that identifies and verifies potential DoH servers to ensure an up-to-date list is maintained.
bundle_description: $VAR1 = {
          'DNS over HTTPS' => 'DNS traffic that is encrypted and obfuscated with HTTPS. DoH domains are extracted from an automated process that identifies and verifies potential DoH servers to ensure an up-to-date list is maintained.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_dns_over_https",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- 233py.com
    { 0, 4624, 'dns.233py.com' },
    { 0, 4624, 'doh.233py.com' },

    -- 360.cn
    { 0, 4624, 'doh.360.cn' },

    -- 42l.fr
    { 0, 4624, 'doh.42l.fr' },

    -- 5ososea.com
    { 0, 4624, 'dns.5ososea.com' },

    -- aa.net.uk
    { 0, 4624, 'dns.aa.net.uk' },

    -- aaflalo.me
    { 0, 4624, 'dns-gcp.aaflalo.me' },
    { 0, 4624, 'dns-nyc.aaflalo.me' },
    { 0, 4624, 'dns.aaflalo.me' },

    -- abmb.win
    { 0, 4624, 'doh.abmb.win' },
    { 0, 4624, 'doh2.abmb.win' },

    -- AdGuard
    { 0, 4624, 'dns-family.adguard.com' },
    { 0, 4624, 'dns-unfiltered.adguard.com' },
    { 0, 4624, 'dns.adguard.com' },

    -- adguard-dns.com
    { 0, 4624, 'dns.adguard-dns.com' },
    { 0, 4624, 'f72da14a.d.adguard-dns.com' },
    { 0, 4624, 'family.adguard-dns.com' },
    { 0, 4624, 'unfiltered.adguard-dns.com' },

    -- ahadns.net
    { 0, 4624, 'doh.au.ahadns.net' },
    { 0, 4624, 'doh.chi.ahadns.net' },
    { 0, 4624, 'doh.es.ahadns.net' },
    { 0, 4624, 'doh.in.ahadns.net' },
    { 0, 4624, 'doh.it.ahadns.net' },
    { 0, 4624, 'doh.la.ahadns.net' },
    { 0, 4624, 'doh.nl.ahadns.net' },
    { 0, 4624, 'doh.no.ahadns.net' },
    { 0, 4624, 'doh.ny.ahadns.net' },
    { 0, 4624, 'doh.pl.ahadns.net' },
    { 0, 4624, 'dot.au.ahadns.net' },
    { 0, 4624, 'dot.chi.ahadns.net' },
    { 0, 4624, 'dot.es.ahadns.net' },
    { 0, 4624, 'dot.in.ahadns.net' },
    { 0, 4624, 'dot.it.ahadns.net' },
    { 0, 4624, 'dot.la.ahadns.net' },
    { 0, 4624, 'dot.nl.ahadns.net' },
    { 0, 4624, 'dot.no.ahadns.net' },
    { 0, 4624, 'dot.ny.ahadns.net' },
    { 0, 4624, 'dot.pl.ahadns.net' },
    { 0, 4624, 'la.ahadns.net' },
    { 0, 4624, 'nl.ahadns.net' },

    -- alekberg.net
    { 0, 4624, 'dns.alekberg.net' },
    { 0, 4624, 'dns2.alekberg.net' },
    { 0, 4624, 'dnses.alekberg.net' },
    { 0, 4624, 'dnsnl.alekberg.net' },
    { 0, 4624, 'dnsse.alekberg.net' },

    -- alidns.com
    { 0, 4624, 'dns.alidns.com' },

    -- amazon.dev
    { 0, 4624, 'e4.dns.na.online-panel.advertising.amazon.dev' },
    { 0, 4624, 'e6.dns.na.online-panel.advertising.amazon.dev' },
    { 0, 4624, 'e9.dns.na.online-panel.advertising.amazon.dev' },

    -- anonymous.pw
    { 0, 4624, 'dns.anonymous.pw' },

    -- Apple
    { 0, 4624, 'doh.dns.apple.com' },

    -- applied-privacy.net
    { 0, 4624, 'doh.applied-privacy.net' },
    { 0, 4624, 'doh.appliedprivacy.net' },
    { 0, 4624, 'dot1.applied-privacy.net' },

    -- arapurayil.com
    { 0, 4624, 'dns.arapurayil.com' },

    -- armadillodns.net
    { 0, 4624, 'doh.armadillodns.net' },

    -- as203038.net
    { 0, 4624, 'resolver.as203038.net' },

    -- att.net
    { 0, 4624, 'dohtrial.att.net' },

    -- b-cdn.net
    { 0, 4624, 'doh1.b-cdn.net' },
    { 0, 4624, 'doh2.b-cdn.net' },

    -- b33.network
    { 0, 4624, 'dns.b33.network' },

    -- ballichar.de
    { 0, 4624, 'dns.ballichar.de' },

    -- belnet.be
    { 0, 4624, 'dns.belnet.be' },

    -- bitdefender.net
    { 0, 4624, 'dns.bitdefender.net' },
    { 0, 4624, 'fra-dns.bitdefender.net' },
    { 0, 4624, 'irl-dns.bitdefender.net' },
    { 0, 4624, 'lon-dns.bitdefender.net' },
    { 0, 4624, 'nvi-dns.bitdefender.net' },
    { 0, 4624, 'ore-dns.bitdefender.net' },
    { 0, 4624, 'tky-dns.bitdefender.net' },

    -- blahdns.com
    { 0, 4624, 'doh-ch.blahdns.com' },
    { 0, 4624, 'doh-de.blahdns.com' },
    { 0, 4624, 'doh-fi.blahdns.com' },
    { 0, 4624, 'doh-jp.blahdns.com' },
    { 0, 4624, 'doh-sg.blahdns.com' },
    { 0, 4624, 'doh1.blahdns.com' },
    { 0, 4624, 'doh2.blahdns.com' },
    { 0, 4624, 'dot-ch.blahdns.com' },
    { 0, 4624, 'dot-de.blahdns.com' },
    { 0, 4624, 'dot-sg.blahdns.com' },

    -- blissdns.net
    { 0, 4624, 'us1.blissdns.net' },

    -- blockerdns.com
    { 0, 4624, 'doh.blockerdns.com' },

    -- blokada.org
    { 0, 4624, 'dns.blokada.org' },

    -- blurams.com
    { 0, 4624, 'dns.blurams.com' },

    -- bortzmeyer.fr
    { 0, 4624, 'doh.bortzmeyer.fr' },

    -- brahma.world
    { 0, 4624, 'dns.brahma.world' },

    -- bravedns.com
    { 0, 4624, 'bravedns.com' },

    -- bt.com
    { 0, 4624, 'doh.bt.com' },

    -- btb.dog
    { 0, 4624, 'dns.btb.dog' },

    -- cachescrubber.org
    { 0, 4624, 'nc.cachescrubber.org' },

    -- captnemo.in
    { 0, 4624, 'doh.captnemo.in' },

    -- censurfridns.dk
    { 0, 4624, 'anycast.censurfridns.dk' },
    { 0, 4624, 'deic-lgb.anycast.censurfridns.dk' },
    { 0, 4624, 'deic-ore.anycast.censurfridns.dk' },
    { 0, 4624, 'kracon.anycast.censurfridns.dk' },
    { 0, 4624, 'rgnet-iad.anycast.censurfridns.dk' },
    { 0, 4624, 'unicast.censurfridns.dk' },

    -- cert.ee
    { 0, 4624, 'dns.cert.ee' },
    { 0, 4624, 'ns1.rpz.cert.ee' },
    { 0, 4624, 'ns2.rpz.cert.ee' },

    -- cgnat.net
    { 0, 4624, 'ibuki.cgnat.net' },

    -- cheazey.net
    { 0, 4624, 'dns2.cheazey.net' },

    -- cira.ca
    { 0, 4624, 'canadianshield.cira.ca' },
    { 0, 4624, 'family.canadianshield.cira.ca' },
    { 0, 4624, 'private.canadianshield.cira.ca' },
    { 0, 4624, 'protected.canadianshield.cira.ca' },

    -- circl.lu
    { 0, 4624, 'crd.circl.lu' },
    { 0, 4624, 'dns.circl.lu' },

    -- Cisco Umbrella / OpenDNS
    { 0, 4624, 'dns.opendns.com' },
    { 0, 4624, 'doh.familyshield.opendns.com' },
    { 0, 4624, 'doh.opendns.com' },
    { 0, 4624, 'doh.sandbox.opendns.com' },
    { 0, 4624, 'familyshield.opendns.com' },
    { 0, 4624, 'sandbox.opendns.com' },

    -- CleanBrowsing
    { 0, 4624, 'adult-filter-dns.cleanbrowsing.org' },
    { 0, 4624, 'adult-filter2-dns2.cleanbrowsing.org' },
    { 0, 4624, 'cello2.cleanbrowsing.org' },
    { 0, 4624, 'custom31335cd6e175f688.dot.cleanbrowsing.org' },
    { 0, 4624, 'custom561423e3e3417cf2.dot.cleanbrowsing.org' },
    { 0, 4624, 'custom6cbb5f8a3fddbfe3.dot.cleanbrowsing.org' },
    { 0, 4624, 'customcf3495547ecf32de.dot.cleanbrowsing.org' },
    { 0, 4624, 'dns.cleanbrowsing.org' },
    { 0, 4624, 'doh.cleanbrowsing.org' },
    { 0, 4624, 'family-filter-dns.cleanbrowsing.org' },
    { 0, 4624, 'family-filter-dns2.cleanbrowsing.org' },
    { 0, 4624, 'security-filter-dns.cleanbrowsing.org' },
    { 0, 4624, 'security-filter-dns2.cleanbrowsing.org' },

    -- CloudFlare
    { 0, 4624, '1dot1dot1dot1.cloudflare-dns.com' },
    { 0, 4624, 'chrome.cloudflare-dns.com' },
    { 0, 4624, 'cloudflare-dns.com' },
    { 0, 4624, 'cloudflare.cloudflare-dns.com' },
    { 0, 4624, 'dns.cloudflare.com' },
    { 0, 4624, 'family.cloudflare-dns.com' },
    { 0, 4624, 'firefox.cloudflare-dns.com' },
    { 0, 4624, 'ipv6a.cloudflare-dns.com' },
    { 0, 4624, 'ipv6b.cloudflare-dns.com' },
    { 0, 4624, 'mozilla.cloudflare-dns.com' },
    { 0, 4624, 'opera.cloudflare-dns.com' },
    { 0, 4624, 'security.cloudflare-dns.com' },
    { 0, 4624, 'tunnelbear.cloudflare-dns.com' },

    -- cmrg.net
    { 0, 4624, 'dns.cmrg.net' },

    -- com.ph
    { 0, 4624, 'clinicsys.doh.com.ph' },

    -- Comcast
    { 0, 4624, 'doh.gslb2.xfinity.com' },
    { 0, 4624, 'doh.xfinity.com' },

    -- containerpi.com
    { 0, 4624, 'dns.containerpi.com' },

    -- controld.com
    { 0, 4624, '1n2sfdkhcgw-s22u.dns.controld.com' },
    { 0, 4624, '1sasiiix3ge-s22.dns.controld.com' },
    { 0, 4624, 'dns.controld.com' },
    { 0, 4624, 'freedns.controld.com' },
    { 0, 4624, 'p0.freedns.controld.com' },
    { 0, 4624, 'p1.freedns.controld.com' },
    { 0, 4624, 'p2.freedns.controld.com' },
    { 0, 4624, 'p3.freedns.controld.com' },
    { 0, 4624, 'p4.freedns.controld.com' },
    { 0, 4624, 'p5.freedns.controld.com' },
    { 0, 4624, 's1.freedns.controld.com' },
    { 0, 4624, 's2.freedns.controld.com' },
    { 0, 4624, 's3.freedns.controld.com' },
    { 0, 4624, 's4.freedns.controld.com' },
    { 0, 4624, 's5.freedns.controld.com' },
    { 0, 4624, 'yq1cgzygpa.dns.controld.com' },

    -- coxlab.net
    { 0, 4624, 'dohdot.coxlab.net' },

    -- crypto.sx
    { 0, 4624, 'doh.crypto.sx' },

    -- csa-rz.de
    { 0, 4624, 'dns.csa-rz.de' },

    -- CZ.NIC
    { 0, 4624, 'odvr.nic.cz' },

    -- datahata.by
    { 0, 4624, 'doh.datahata.by' },

    -- ddns.net
    { 0, 4624, 'jit.ddns.net' },

    -- decentraweb.org
    { 0, 4624, 'dns.decentraweb.org' },

    -- decloudus.com
    { 0, 4624, 'dns.decloudus.com' },

    -- defaultroutes.de
    { 0, 4624, 'doh.defaultroutes.de' },

    -- developer.li
    { 0, 4624, 'dns.developer.li' },
    { 0, 4624, 'dns2.developer.li' },

    -- digitalcourage.de
    { 0, 4624, 'dns2.digitalcourage.de' },
    { 0, 4624, 'dns3.digitalcourage.de' },

    -- digitale-gesellschaft.ch
    { 0, 4624, 'dns.digitale-gesellschaft.ch' },
    { 0, 4624, 'dns1.digitale-gesellschaft.ch' },
    { 0, 4624, 'dns2.digitale-gesellschaft.ch' },

    -- digitalsize.net
    { 0, 4624, 'dns.digitalsize.net' },

    -- dismail.de
    { 0, 4624, 'fdns1.dismail.de' },
    { 0, 4624, 'fdns2.dismail.de' },

    -- dns-over-https.com
    { 0, 4624, 'dns.dns-over-https.com' },

    -- dns.pt
    { 0, 4624, 'nuvem.dns.pt' },

    -- dns.pub
    { 0, 4624, 'dns.pub' },

    -- DNS.SB
    { 0, 4624, 'doh.dns.sb' },
    { 0, 4624, 'public-dns-a.dns.sb' },
    { 0, 4624, 'public-dns-b.dns.sb' },

    -- dns.toys
    { 0, 4624, 'www.dns.toys' },

    -- dns0.eu
    { 0, 4624, 'dns0.eu' },
    { 0, 4624, 'zero.dns0.eu' },

    -- dnsbycomodo.com
    { 0, 4624, 'ns1.recursive.dnsbycomodo.com' },
    { 0, 4624, 'ns2.recursive.dnsbycomodo.com' },

    -- dnscrypt.ca
    { 0, 4624, 'dns1.dnscrypt.ca' },
    { 0, 4624, 'dns2.dnscrypt.ca' },

    -- dnscrypt.uk
    { 0, 4624, 'doh.dnscrypt.uk' },

    -- dnsfilter.com
    { 0, 4624, 'dns1.dnsfilter.com' },
    { 0, 4624, 'dns2.dnsfilter.com' },
    { 0, 4624, 'doh.dnsfilter.com' },

    -- dnsforfamily.com
    { 0, 4624, 'dns-doh-no-safe-search.dnsforfamily.com' },
    { 0, 4624, 'dns-doh.dnsforfamily.com' },

    -- dnsforge.de
    { 0, 4624, 'dnsforge.de' },

    -- dnshome.de
    { 0, 4624, 'dns.dnshome.de' },

    -- DNSlify
    { 0, 4624, 'doh.dnslify.com' },

    -- dnsoverhttps.net
    { 0, 4624, 'dns.dnsoverhttps.net' },

    -- dnswarden.com
    { 0, 4624, 'doh.asia.dnswarden.com' },
    { 0, 4624, 'doh.dnswarden.com' },
    { 0, 4624, 'doh.eu.dnswarden.com' },
    { 0, 4624, 'doh.us.dnswarden.com' },
    { 0, 4624, 'dot.dnswarden.com' },

    -- doh-beta.e-paths
    { 0, 4624, 'doh-beta.e-paths' },

    -- doh.li
    { 0, 4624, 'doh.li' },

    -- doh.pub
    { 0, 4624, 'doh.pub' },

    -- doh.sb
    { 0, 4624, 'ca-yyz.doh.sb' },
    { 0, 4624, 'de-dus.doh.sb' },
    { 0, 4624, 'doh.sb' },

    -- dot.pub
    { 0, 4624, 'dot.pub' },

    -- dva.re
    { 0, 4624, 'dns.dva.re' },

    -- emeraldonion.org
    { 0, 4624, 'dns.emeraldonion.org' },

    -- example.com
    { 0, 4624, 'dns.example.com' },

    -- fdn.fr
    { 0, 4624, 'ns0.fdn.fr' },
    { 0, 4624, 'ns1.fdn.fr' },

    -- ffmuc.net
    { 0, 4624, 'doh.ffmuc.net' },
    { 0, 4624, 'dot.ffmuc.net' },
    { 0, 4624, 'sendlingertor.ffmuc.net' },

    -- gamban.com
    { 0, 4624, 'dns.gamban.com' },

    -- getdnsapi.net
    { 0, 4624, 'getdnsapi.net' },

    -- gi.co.id
    { 0, 4624, 'dns.gi.co.id' },

    -- Google
    { 0, 4624, 'dns.google' },
    { 0, 4624, 'dns.google.com' },
    { 0, 4624, 'google-public-dns-a.google.com' },
    { 0, 4624, 'google-public-dns-b.google.com' },

    -- greatwhite.tech
    { 0, 4624, 'my.greatwhite.tech' },

    -- hdns.io
    { 0, 4624, 'a.hdns.io' },
    { 0, 4624, 'b.hdns.io' },

    -- he.net
    { 0, 4624, 'ordns.he.net' },

    -- hhgasdygqwueysbjadasghds.com
    { 0, 4624, 'fn6pma--2e617054721265b--y74n8f.hhgasdygqwueysbjadasghds.com' },

    -- hinet.net
    { 0, 4624, 'dns.hinet.net' },

    -- hostux.net
    { 0, 4624, 'dns.front1.hostux.net' },
    { 0, 4624, 'dns.front2.hostux.net' },
    { 0, 4624, 'dns.hostux.net' },

    -- i2pd.xyz
    { 0, 4624, 'opennic.i2pd.xyz' },
    { 0, 4624, 'opennic2.i2pd.xyz' },

    -- icanhas.net
    { 0, 4624, 'corax.icanhas.net' },

    -- IIJ
    { 0, 4624, 'public.dns.iij.jp' },
    { 0, 4624, 'public00.dns.iij.jp' },
    { 0, 4624, 'public01.dns.iij.jp' },

    -- ikarem.io
    { 0, 4624, 'doh.dev.ikarem.io' },

    -- ipoac.nl
    { 0, 4624, 'ipoac.nl' },

    -- iriseden.fr
    { 0, 4624, 'ns1-doh.iriseden.fr' },
    { 0, 4624, 'ns2-doh.iriseden.fr' },
    { 0, 4624, 'ns2.iriseden.fr' },

    -- jabber-germany.de
    { 0, 4624, 'www.jabber-germany.de' },

    -- jd.com
    { 0, 4624, 'dns.jd.com' },

    -- jd.id
    { 0, 4624, 'dns.jd.id' },

    -- lars-lehmann.net
    { 0, 4624, 'dns.lars-lehmann.net' },

    -- lavate.ch
    { 0, 4624, 'dns.lavate.ch' },

    -- lelux.fi
    { 0, 4624, 'resolver-eu.lelux.fi' },

    -- libredns
    { 0, 4624, 'doh.libredns.gr' },
    { 0, 4624, 'doh.libredns.org' },
    { 0, 4624, 'libredns.gr' },

    -- licoho.de
    { 0, 4624, 'ns-doh.licoho.de' },

    -- linuxsec.org
    { 0, 4624, 'doh.linuxsec.org' },

    -- liquidtelecom.net
    { 0, 4624, 'africadns2.liquidtelecom.net' },

    -- luckysrv.de
    { 0, 4624, 'v2202303112961222044.luckysrv.de' },

    -- meganerd.nl
    { 0, 4624, 'chewbacca.meganerd.nl' },

    -- melalandia.tk
    { 0, 4624, 'dns.melalandia.tk' },

    -- meraki.com
    { 0, 4624, 'doh.meraki.com' },

    -- monzoon.net
    { 0, 4624, 'zrh1-ns01.monzoon.net' },

    -- morbitzer.de
    { 0, 4624, 'www.morbitzer.de' },

    -- moulticast.net
    { 0, 4624, 'dns.moulticast.net' },

    -- mrkaran.dev
    { 0, 4624, 'dns.mrkaran.dev' },

    -- mullvad.net
    { 0, 4624, 'adblock.doh.mullvad.net' },
    { 0, 4624, 'doh.mullvad.net' },

    -- mydns.network
    { 0, 4624, 'adblock.mydns.network' },

    -- netweaver.uk
    { 0, 4624, 'doh.netweaver.uk' },

    -- neutopia.org
    { 0, 4624, 'dns.neutopia.org' },

    -- nextdns.io
    { 0, 4624, '14c29b.dns.nextdns.io' },
    { 0, 4624, '1dd869.dns.nextdns.io' },
    { 0, 4624, '34c239.dns.nextdns.io' },
    { 0, 4624, '365ea2.dns.nextdns.io' },
    { 0, 4624, '36b983.dns.nextdns.io' },
    { 0, 4624, '38121d.dns.nextdns.io' },
    { 0, 4624, '4a-bd7749.dns.nextdns.io' },
    { 0, 4624, '516369.dns.nextdns.io' },
    { 0, 4624, '5757d8.dns.nextdns.io' },
    { 0, 4624, '5e3df2.dns.nextdns.io' },
    { 0, 4624, '67d39e.dns.nextdns.io' },
    { 0, 4624, '74cc3f.dns.nextdns.io' },
    { 0, 4624, '7d6259.dns.nextdns.io' },
    { 0, 4624, '7f3ace.dns.nextdns.io' },
    { 0, 4624, '86837a.dns.nextdns.io' },
    { 0, 4624, '8f6e96.dns.nextdns.io' },
    { 0, 4624, 'anycast.dns.nextdns.io' },
    { 0, 4624, 'anycsast.dns.nextdns.io' },
    { 0, 4624, 'apple.dns.nextdns.io' },
    { 0, 4624, 'b6c6cf.dns.nextdns.io' },
    { 0, 4624, 'bc5493.dns.nextdns.io' },
    { 0, 4624, 'bf973f.dns.nextdns.io' },
    { 0, 4624, 'blade-e2c85b.dns.nextdns.io' },
    { 0, 4624, 'chromium.dns.nextdns.io' },
    { 0, 4624, 'd13ccf.dns.nextdns.io' },
    { 0, 4624, 'deb7e1.dns.nextdns.io' },
    { 0, 4624, 'dns.nextdns.io' },
    { 0, 4624, 'dns1.nextdns.io' },
    { 0, 4624, 'dns2.nextdns.io' },
    { 0, 4624, 'do-blr-1.edge.nextdns.io' },
    { 0, 4624, 'ebbbd8.dns.nextdns.io' },
    { 0, 4624, 'firefox.dns.nextdns.io' },
    { 0, 4624, 'hkpixel3-f1a1bf.dns.nextdns.io' },
    { 0, 4624, 'hkpixel6p-f1a1bf.dns.nextdns.io' },
    { 0, 4624, 'ios.dns.nextdns.io' },
    { 0, 4624, 'jasons20-84231a.dns.nextdns.io' },
    { 0, 4624, 'matt--pixel5-7b672e.dns.nextdns.io' },
    { 0, 4624, 'mikesnote-24591b.dns.nextdns.io' },
    { 0, 4624, 'mobile--1-5d5eb2.dns.nextdns.io' },
    { 0, 4624, 'n61-21e22b.dns.nextdns.io' },
    { 0, 4624, 'note10-f594c6.dns.nextdns.io' },
    { 0, 4624, 'note10plus-1e86d3.dns.nextdns.io' },
    { 0, 4624, 'ns1.nextdns.io' },
    { 0, 4624, 'ns2.nextdns.io' },
    { 0, 4624, 'oneplus--3t-5674b8.dns.nextdns.io' },
    { 0, 4624, 'oneplus--one-5674b8.dns.nextdns.io' },
    { 0, 4624, 'pixel4-aa1e79.dns.nextdns.io' },
    { 0, 4624, 'pixel6-3e8e94.dns.nextdns.io' },
    { 0, 4624, 'pxl5a-c7cd97.dns.nextdns.io' },
    { 0, 4624, 's10e-bd7749.dns.nextdns.io' },
    { 0, 4624, 's21-ultra-3e7824.dns.nextdns.io' },
    { 0, 4624, 's5e-bd7749.dns.nextdns.io' },
    { 0, 4624, 's5ea-bd7749.dns.nextdns.io' },
    { 0, 4624, 'trr.dns.nextdns.io' },
    { 0, 4624, 'windows.dns.nextdns.io' },

    -- nic.lv
    { 0, 4624, 'doh.nic.lv' },

    -- nixnet.xyz
    { 0, 4624, 'dns.nixnet.xyz' },
    { 0, 4624, 'uncensored.lv1.dns.nixnet.xyz' },
    { 0, 4624, 'uncensored.ny1.dns.nixnet.xyz' },

    -- njal.la
    { 0, 4624, 'dns.njal.la' },

    -- noaddns.com
    { 0, 4624, 'resolver.noaddns.com' },

    -- nsx.de
    { 0, 4624, 'dns.nsx.de' },

    -- one.one
    { 0, 4624, 'one.one.one.one' },

    -- openinternet.io
    { 0, 4624, 'resolver4.dns.openinternet.io' },

    -- opennameserver.org
    { 0, 4624, 'ns1.opennameserver.org' },

    -- oszx.co
    { 0, 4624, 'dns.oszx.co' },

    -- pch.net
    { 0, 4624, 'rpz-public-resolver1.rrdns.pch.net' },

    -- pistada.com
    { 0, 4624, 'pistada.com' },

    -- plan9-ns2.com
    { 0, 4624, 'draco.plan9-ns2.com' },

    -- pokemonrevolution.net
    { 0, 4624, 'dns.pokemonrevolution.net' },

    -- post-factum.tk
    { 0, 4624, 'doh.post-factum.tk' },

    -- powerdns.org
    { 0, 4624, 'doh.powerdns.org' },

    -- pumplex.com
    { 0, 4624, 'dns.pumplex.com' },

    -- purewash.es
    { 0, 4624, 'purewash.es' },

    -- Quad9
    { 0, 4624, 'dns-nosec.quad9.net' },
    { 0, 4624, 'dns.quad9.net' },
    { 0, 4624, 'dns10.quad9.net' },
    { 0, 4624, 'dns11.quad9.net' },
    { 0, 4624, 'dns12.quad9.net' },
    { 0, 4624, 'dns9.quad9.net' },

    -- qwer.pw
    { 0, 4624, 'ant.dns.qwer.pw' },
    { 0, 4624, 'cat.dns.qwer.pw' },
    { 0, 4624, 'dog.dns.qwer.pw' },
    { 0, 4624, 'frog.dns.qwer.pw' },
    { 0, 4624, 'lion.dns.qwer.pw' },
    { 0, 4624, 'tiger.dns.qwer.pw' },

    -- r0cket.net
    { 0, 4624, 'resolver.r0cket.net' },

    -- rubyfish.cn
    { 0, 4624, '13800000000.rubyfish.cn' },
    { 0, 4624, 'aliyun.rubyfish.cn' },
    { 0, 4624, 'dns.rubyfish.cn' },
    { 0, 4624, 'rubyfish.cn' },
    { 0, 4624, 'v6.rubyfish.cn' },

    -- ryan-palmer.com
    { 0, 4624, 'dns1.ryan-palmer.com' },

    -- safeservedns.com
    { 0, 4624, 'safeservedns.com' },

    -- sant.sh
    { 0, 4624, 'dns.sant.sh' },

    -- scapetical.com
    { 0, 4624, 'dns.scapetical.com' },

    -- seby.io
    { 0, 4624, 'dns.seby.io' },
    { 0, 4624, 'doh-2.seby.io' },
    { 0, 4624, 'doh.seby.io' },
    { 0, 4624, 'dot.seby.io' },

    -- sec511.com
    { 0, 4624, 'dns.sec511.com' },

    -- securedns.eu
    { 0, 4624, 'doh.securedns.eu' },

    -- segurodns.net
    { 0, 4624, 'doh.us1.segurodns.net' },

    -- shadabshamsi.com
    { 0, 4624, 'ecs.shadabshamsi.com' },

    -- shecan.ir
    { 0, 4624, 'dns.shecan.ir' },
    { 0, 4624, 'free.shecan.ir' },

    -- sinodun.com
    { 0, 4624, 'dnsovertls.sinodun.com' },
    { 0, 4624, 'dnsovertls1.sinodun.com' },

    -- snopyta.org
    { 0, 4624, 'fi.doh.dns.snopyta.org' },

    -- surfshark.com
    { 0, 4624, 'dns.surfshark.com' },

    -- switch.ch
    { 0, 4624, 'dns-cache.switch.ch' },
    { 0, 4624, 'dns-cache2.switch.ch' },
    { 0, 4624, 'dns.switch.ch' },

    -- synology.me
    { 0, 4624, 'ibksturm.synology.me' },

    -- sys-adm.in
    { 0, 4624, 'bld-o1.sys-adm.in' },

    -- t53.de
    { 0, 4624, 'dns.t53.de' },

    -- therifleman.name
    { 0, 4624, 'dns.therifleman.name' },

    -- tiar.app
    { 0, 4624, 'doh.tiar.app' },
    { 0, 4624, 'doh.tiarap.org' },
    { 0, 4624, 'dot.tiar.app' },
    { 0, 4624, 'jp.tiar.app' },
    { 0, 4624, 'jp.tiarap.org' },

    -- twnic.tw
    { 0, 4624, 'dns.twnic.tw' },

    -- umbrella.com
    { 0, 4624, 'dns.umbrella.com' },
    { 0, 4624, 'doh.umbrella.com' },

    -- uncensoreddns.org
    { 0, 4624, 'anycast.uncensoreddns.org' },
    { 0, 4624, 'unicast.uncensoreddns.org' },

    -- utangard.net
    { 0, 4624, 'dns.utangard.net' },

    -- wa.gov
    { 0, 4624, 'vaccinelocator.doh.wa.gov' },

    -- web.id
    { 0, 4624, 'doh.this.web.id' },

    -- wil.cloud
    { 0, 4624, 'dns-1.wil.cloud' },

    -- wugui.zone
    { 0, 4624, 'dns-asia.wugui.zone' },
    { 0, 4624, 'dns.wugui.zone' },

    -- yepdns.com
    { 0, 4624, 'sg.yepdns.com' },

    -- yyun8.com
    { 0, 4624, 'dns.yyun8.com' },

    -- zjurl.cn
    { 0, 4624, 'doh.zjurl.cn' },
}

gHostPortAppList = {
    -- AdGuard
    { 0, 4624, "176.103.130.130", 443, DC.ipproto.tcp},
    { 0, 4624, "176.103.130.131", 443, DC.ipproto.tcp},
    { 0, 4624, "176.103.130.132", 443, DC.ipproto.tcp},
    { 0, 4624, "176.103.130.134", 443, DC.ipproto.tcp},

    -- CleanBrowsing
    { 0, 4624, "185.228.168.168", 443, DC.ipproto.tcp},
    { 0, 4624, "185.228.169.168", 443, DC.ipproto.tcp},
    { 0, 4624, "185.228.168.10", 443, DC.ipproto.tcp},
    { 0, 4624, "185.228.169.11", 443, DC.ipproto.tcp},
    { 0, 4624, "185.228.168.9", 443, DC.ipproto.tcp},
    { 0, 4624, "185.228.169.9", 443, DC.ipproto.tcp},

    -- CloudFlare
    { 0, 4624, "104.16.249.249", 443, DC.ipproto.tcp},
    { 0, 4624, "104.18.2.55", 443, DC.ipproto.tcp},
    { 0, 4624, "104.18.27.128", 443, DC.ipproto.tcp},
    { 0, 4624, "1.1.1.1", 443, DC.ipproto.tcp},
    { 0, 4624, "1.0.0.1", 443, DC.ipproto.tcp},
    { 0, 4624, "1.1.1.2", 443, DC.ipproto.tcp},
    { 0, 4624, "1.0.0.2", 443, DC.ipproto.tcp},
    { 0, 4624, "1.1.1.3", 443, DC.ipproto.tcp},
    { 0, 4624, "1.0.0.3", 443, DC.ipproto.tcp},

    -- Google
    { 0, 4624, "8.8.8.8", 443, DC.ipproto.tcp},
    { 0, 4624, "8.8.4.4", 443, DC.ipproto.tcp},

    -- Cisco Umbrella / OpenDNS
    { 0, 4624, "208.67.222.222", 443, DC.ipproto.tcp},
    { 0, 4624, "208.67.220.220", 443, DC.ipproto.tcp},
    { 0, 4624, "208.67.222.123", 443, DC.ipproto.tcp},
    { 0, 4624, "208.67.220.123", 443, DC.ipproto.tcp},
    { 0, 4624, "208.67.222.2", 443, DC.ipproto.tcp},
    { 0, 4624, "208.67.220.2", 443, DC.ipproto.tcp},
    { 0, 4624, "146.112.41.2", 443, DC.ipproto.tcp},
    { 0, 4624, "146.112.41.3", 443, DC.ipproto.tcp},

    -- Quad9
    { 0, 4624, "9.9.9.9", 443, DC.ipproto.tcp},
    { 0, 4624, "9.9.9.10", 443, DC.ipproto.tcp},
    { 0, 4624, "149.112.112.9", 443, DC.ipproto.tcp},
    { 0, 4624, "149.112.112.10", 443, DC.ipproto.tcp},
    { 0, 4624, "149.112.112.11", 443, DC.ipproto.tcp},
    { 0, 4624, "149.112.112.112", 443, DC.ipproto.tcp},

    -- Comcast
    { 0, 4624, "96.113.151.148", 443, DC.ipproto.tcp},

    -- CZ.NIC
    { 0, 4624, "185.43.135.1", 443, DC.ipproto.tcp},

    -- DNSlify
    { 0, 4624, "185.235.81.1", 443, DC.ipproto.tcp},

    -- nextdns.io
    { 0, 4624, "45.90.28.0", 443, DC.ipproto.tcp},

    -- DNS.SB
    { 0, 4624, "104.27.159.178", 443, DC.ipproto.tcp},

    -- IIJ
    { 0, 4624, "103.2.57.5", 443, DC.ipproto.tcp},
}

function DetectorInit(detectorInstance)
    gDetector = detectorInstance;
    if gDetector.addHostPortApp then
        for i,v in ipairs(gHostPortAppList) do
            gDetector:addHostPortApp(v[1],v[2],v[3],v[4],v[5]);
        end
    end

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end
