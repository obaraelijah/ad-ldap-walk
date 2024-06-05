use ldap3::SearchEntry;
use std::cmp::Ordering;

/**
 * Extract the first element of an a LDAP search entry
 */
pub fn get_attr<'a>(result: &'a SearchEntry, attr: &'static str) -> Option<&'a str> {
    if let Some(Some(value)) = result.attrs.get(attr).map(|cns| cns.get(0)) {
        Some(value)
    } else {
        None
    }
}

pub fn cmp_attr(result_a: &SearchEntry, result_b: &SearchEntry, attr: &'static str) -> Ordering {
    match (get_attr(result_a, attr), get_attr(result_b, attr)) {
        (Some(a), Some(b)) => a.cmp(b),
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}
