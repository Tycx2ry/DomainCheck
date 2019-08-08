#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.review import DomainReview
import sys


def domaincheck(domain, vt_api):
    lab_results = {}
    domain_categories = []
    burned_explanations = []
    burned_dns = False
    health = 'Healthy'
    health_dns = 'Healthy'
    dr = DomainReview(vt_api)
    malware_domains = dr.download_malware_domains()

    # Check if domain is flagged for malware
    if malware_domains:
        if domain in malware_domains:
            health = 'Burned'
            burned_explanations.append('Flagged by malwaredomains.com')

    # Check domain name with VirusTotal
    vt_results = dr.check_virustotal(domain)
    if 'categories' in vt_results:
        domain_categories = vt_results['categories']

    # Check if VirusTotal has any detections for URLs or samples
    if 'detected_downloaded_samples' in vt_results:
        if len(vt_results['detected_downloaded_samples']) > 0:
            health = 'Burned'
            burned_explanations.append('Tied to a VirusTotal detected malware sample')
    if 'detected_urls' in vt_results:
        if len(vt_results['detected_urls']) > 0:
            health = 'Burned'
            burned_explanations.append('Tied to a VirusTotal detected URL')

    # Get passive DNS results from VirusTotal JSON
    ip_addresses = []
    if 'resolutions' in vt_results:
        for address in vt_results['resolutions']:
            ip_addresses.append(
                {'address': address['ip_address'], 'timestamp': address['last_resolved'].split(" ")[0]})
    bad_addresses = []
    for address in ip_addresses:
        if dr.check_cymon(address['address']):
            burned_dns = True
            bad_addresses.append(address['address'] + '/' + address['timestamp'])
    if burned_dns:
        health_dns = 'Flagged DNS ({})'.format(', '.join(bad_addresses))

    # Collect categories from the other sources
    xforce_results = dr.check_ibm_xforce(domain)
    domain_categories.extend(xforce_results)

    talos_results = dr.check_talos(domain)
    domain_categories.extend(talos_results)

    bluecoat_results = dr.check_bluecoat(domain)
    domain_categories.extend(bluecoat_results)

    fortiguard_results = dr.check_fortiguard(domain)
    domain_categories.extend(fortiguard_results)

    opendns_results = dr.check_opendns(domain)
    domain_categories.extend(opendns_results)

    trendmicro_results = dr.check_trendmicro(domain)
    domain_categories.extend(trendmicro_results)

    mxtoolbox_results = dr.check_mxtoolbox(domain)
    domain_categories.extend(domain_categories)

    # Make categories unique
    domain_categories = list(set(domain_categories))
    # Check if any categopries are suspect
    bad_cats = []
    for category in domain_categories:
        if category.lower() in DomainReview.blacklisted:
            bad_cats.append(category.capitalize())
    if bad_cats:
        health = 'Burned'
        burned_explanations.append('Tagged with a bad category')

    # Assemble the dictionary to return for this domain
    lab_results[domain] = {}
    lab_results[domain]['categories'] = {}

    lab_results[domain]['health'] = health
    lab_results[domain]['burned_explanation'] = ', '.join(burned_explanations)
    lab_results[domain]['health_dns'] = health_dns

    lab_results[domain]['categories']['all'] = domain_categories
    lab_results[domain]['categories']['talos'] = talos_results
    lab_results[domain]['categories']['xforce'] = xforce_results
    lab_results[domain]['categories']['opendns'] = opendns_results
    lab_results[domain]['categories']['bluecoat'] = bluecoat_results
    lab_results[domain]['categories']['mxtoolbox'] = mxtoolbox_results
    lab_results[domain]['categories']['trendmicro'] = trendmicro_results
    lab_results[domain]['categories']['fortiguard'] = fortiguard_results

    return lab_results[domain]


def test(domain):
    dr = DomainReview("")
    print(dr.check_bluecoat(domain))


if __name__ == "__main__":
    vt_api = ""
    result = domaincheck(sys.argv[1], vt_api)
    print(f'''Domain: {sys.argv[1]}
[*] Categories [*]
[-]   Talos: {result['categories']['talos'][0]}
[-]   xforce: {result['categories']['xforce'][0]}
[-]   opendns: {result['categories']['opendns'][0]}
[-]   bluecoat: {result['categories']['bluecoat'][0]}
[-]   mxtoolbox: {result['categories']['mxtoolbox'][0]}
[-]   trendmicro: {result['categories']['trendmicro'][0]}
[-]   fortiguard: {result['categories']['fortiguard'][0]}
[*] Health [*]
[-]   {result['health']}
[*] explanation [*]
[-]   {result['burned_explanation']} 
[*] health dns [*]
[-]   {result['health_dns']}''')
