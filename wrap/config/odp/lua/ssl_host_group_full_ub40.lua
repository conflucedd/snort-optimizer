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
detection_name: SSL Group Full "UB40"
version: 2
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Google Translate' => 'Google translation service.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_full_ub40",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    -- Google Translate
      { 0, 185, 'translate.google.ac' },
      { 0, 185, 'translate.google.ad' },
      { 0, 185, 'translate.google.ae' },
      { 0, 185, 'translate.google.af' },
      { 0, 185, 'translate.google.ag' },
      { 0, 185, 'translate.google.ai' },
      { 0, 185, 'translate.google.al' },
      { 0, 185, 'translate.google.am' },
      { 0, 185, 'translate.google.ao' },
      { 0, 185, 'translate.google.ar' },
      { 0, 185, 'translate.google.as' },
      { 0, 185, 'translate.google.at' },
      { 0, 185, 'translate.google.au' },
      { 0, 185, 'translate.google.az' },
      { 0, 185, 'translate.google.ba' },
      { 0, 185, 'translate.google.bd' },
      { 0, 185, 'translate.google.be' },
      { 0, 185, 'translate.google.bf' },
      { 0, 185, 'translate.google.bg' },
      { 0, 185, 'translate.google.bh' },
      { 0, 185, 'translate.google.bi' },
      { 0, 185, 'translate.google.bj' },
      { 0, 185, 'translate.google.bn' },
      { 0, 185, 'translate.google.bo' },
      { 0, 185, 'translate.google.br' },
      { 0, 185, 'translate.google.bs' },
      { 0, 185, 'translate.google.bt' },
      { 0, 185, 'translate.google.bw' },
      { 0, 185, 'translate.google.by' },
      { 0, 185, 'translate.google.bz' },
      { 0, 185, 'translate.google.ca' },
      { 0, 185, 'translate.google.kh' },
      { 0, 185, 'translate.google.cc' },
      { 0, 185, 'translate.google.cd' },
      { 0, 185, 'translate.google.cf' },
      { 0, 185, 'translate.google.cat' },
      { 0, 185, 'translate.google.cg' },
      { 0, 185, 'translate.google.ch' },
      { 0, 185, 'translate.google.ci' },
      { 0, 185, 'translate.google.ck' },
      { 0, 185, 'translate.google.cl' },
      { 0, 185, 'translate.google.cm' },
      { 0, 185, 'translate.google.cn' },
      { 0, 185, 'translate.google.co' },
      { 0, 185, 'translate.google.cr' },
      { 0, 185, 'translate.google.cu' },
      { 0, 185, 'translate.google.cv' },
      { 0, 185, 'translate.google.cy' },
      { 0, 185, 'translate.google.cz' },
      { 0, 185, 'translate.google.de' },
      { 0, 185, 'translate.google.dj' },
      { 0, 185, 'translate.google.dk' },
      { 0, 185, 'translate.google.dm' },
      { 0, 185, 'translate.google.do' },
      { 0, 185, 'translate.google.dz' },
      { 0, 185, 'translate.google.ec' },
      { 0, 185, 'translate.google.ee' },
      { 0, 185, 'translate.google.eg' },
      { 0, 185, 'translate.google.es' },
      { 0, 185, 'translate.google.et' },
      { 0, 185, 'translate.google.fi' },
      { 0, 185, 'translate.google.fj' },
      { 0, 185, 'translate.google.fm' },
      { 0, 185, 'translate.google.fr' },
      { 0, 185, 'translate.google.ga' },
      { 0, 185, 'translate.google.ge' },
      { 0, 185, 'translate.google.gf' },
      { 0, 185, 'translate.google.gg' },
      { 0, 185, 'translate.google.gh' },
      { 0, 185, 'translate.google.gi' },
      { 0, 185, 'translate.google.gl' },
      { 0, 185, 'translate.google.gm' },
      { 0, 185, 'translate.google.gp' },
      { 0, 185, 'translate.google.gr' },
      { 0, 185, 'translate.google.gt' },
      { 0, 185, 'translate.google.gy' },
      { 0, 185, 'translate.google.hk' },
      { 0, 185, 'translate.google.hn' },
      { 0, 185, 'translate.google.hr' },
      { 0, 185, 'translate.google.ht' },
      { 0, 185, 'translate.google.hu' },
      { 0, 185, 'translate.google.id' },
      { 0, 185, 'translate.google.iq' },
      { 0, 185, 'translate.google.ie' },
      { 0, 185, 'translate.google.il' },
      { 0, 185, 'translate.google.im' },
      { 0, 185, 'translate.google.in' },
      { 0, 185, 'translate.google.io' },
      { 0, 185, 'translate.google.is' },
      { 0, 185, 'translate.google.it' },
      { 0, 185, 'translate.google.je' },
      { 0, 185, 'translate.google.jm' },
      { 0, 185, 'translate.google.jo' },
      { 0, 185, 'translate.google.jp' },
      { 0, 185, 'translate.google.ke' },
      { 0, 185, 'translate.google.ki' },
      { 0, 185, 'translate.google.kg' },
      { 0, 185, 'translate.google.kr' },
      --{ 0, 185, 'translate.google.kw' },
      { 0, 185, 'translate.google.kz' },
      { 0, 185, 'translate.google.la' },
      --{ 0, 185, 'translate.google.lb' },
      { 0, 185, 'translate.google.lc' },
      { 0, 185, 'translate.google.li' },
      { 0, 185, 'translate.google.lk' },
      { 0, 185, 'translate.google.ls' },
      { 0, 185, 'translate.google.lt' },
      { 0, 185, 'translate.google.lu' },
      { 0, 185, 'translate.google.lv' },
      { 0, 185, 'translate.google.ly' },
      { 0, 185, 'translate.google.ma' },
      { 0, 185, 'translate.google.md' },
      { 0, 185, 'translate.google.me' },
      { 0, 185, 'translate.google.mg' },
      { 0, 185, 'translate.google.mk' },
      { 0, 185, 'translate.google.ml' },
      --{ 0, 185, 'translate.google.mm' },
      { 0, 185, 'translate.google.mn' },
      { 0, 185, 'translate.google.ms' },
      { 0, 185, 'translate.google.mt' },
      { 0, 185, 'translate.google.mu' },
      { 0, 185, 'translate.google.mv' },
      { 0, 185, 'translate.google.mw' },
      { 0, 185, 'translate.google.mx' },
      { 0, 185, 'translate.google.my' },
      { 0, 185, 'translate.google.mz' },
      { 0, 185, 'translate.google.na' },
      { 0, 185, 'translate.google.ne' },
      { 0, 185, 'translate.google.nf' },
      { 0, 185, 'translate.google.ng' },
      { 0, 185, 'translate.google.ni' },
      { 0, 185, 'translate.google.nl' },
      { 0, 185, 'translate.google.no' },
      { 0, 185, 'translate.google.np' },
      { 0, 185, 'translate.google.nr' },
      { 0, 185, 'translate.google.nu' },
      { 0, 185, 'translate.google.nz' },
      { 0, 185, 'translate.google.om' },
      { 0, 185, 'translate.google.pk' },
      { 0, 185, 'translate.google.pa' },
      { 0, 185, 'translate.google.pe' },
      { 0, 185, 'translate.google.ph' },
      { 0, 185, 'translate.google.pl' },
      { 0, 185, 'translate.google.pg' },
      { 0, 185, 'translate.google.pn' },
      { 0, 185, 'translate.google.pr' },
      { 0, 185, 'translate.google.ps' },
      { 0, 185, 'translate.google.pt' },
      { 0, 185, 'translate.google.py' },
      { 0, 185, 'translate.google.qa' },
      { 0, 185, 'translate.google.ro' },
      { 0, 185, 'translate.google.rs' },
      { 0, 185, 'translate.google.ru' },
      { 0, 185, 'translate.google.rw' },
      { 0, 185, 'translate.google.sa' },
      { 0, 185, 'translate.google.sb' },
      { 0, 185, 'translate.google.sc' },
      { 0, 185, 'translate.google.se' },
      { 0, 185, 'translate.google.sg' },
      { 0, 185, 'translate.google.sh' },
      { 0, 185, 'translate.google.si' },
      { 0, 185, 'translate.google.sk' },
      { 0, 185, 'translate.google.sl' },
      { 0, 185, 'translate.google.sn' },
      { 0, 185, 'translate.google.sm' },
      { 0, 185, 'translate.google.so' },
      { 0, 185, 'translate.google.st' },
      { 0, 185, 'translate.google.sr' },
      --{ 0, 185, 'translate.google.sv' },
      { 0, 185, 'translate.google.td' },
      { 0, 185, 'translate.google.tg' },
      { 0, 185, 'translate.google.th' },
      { 0, 185, 'translate.google.tj' },
      { 0, 185, 'translate.google.tk' },
      { 0, 185, 'translate.google.tl' },
      { 0, 185, 'translate.google.tm' },
      { 0, 185, 'translate.google.to' },
      { 0, 185, 'translate.google.tn' },
      { 0, 185, 'translate.google.tr' },
      { 0, 185, 'translate.google.tt' },
      { 0, 185, 'translate.google.tw' },
      { 0, 185, 'translate.google.tz' },
      { 0, 185, 'translate.google.ua' },
      --{ 0, 185, 'translate.google.ug' },
      { 0, 185, 'translate.google.uk' },
      { 0, 185, 'translate.google.us' },
      { 0, 185, 'translate.google.uy' },
      { 0, 185, 'translate.google.uz' },
      { 0, 185, 'translate.google.vc' },
      { 0, 185, 'translate.google.ve' },
      { 0, 185, 'translate.google.vg' },
      { 0, 185, 'translate.google.vi' },
      { 0, 185, 'translate.google.vn' },
      { 0, 185, 'translate.google.vu' },
      { 0, 185, 'translate.google.ws' },
      { 0, 185, 'translate.google.za' },
      { 0, 185, 'translate.google.zm' },
      { 0, 185, 'translate.google.zw' },
}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end
    return gDetector;
end

function DetectorClean()
end
