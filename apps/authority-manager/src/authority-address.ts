import { isIP } from "node:net";

export interface AuthorityAddress {
  host: string;
  port: number;
}

export interface AuthorityAddressOptions {
  label: string;
  allowedSchemes?: readonly string[];
}

// One canonical parser for every authority TCP boundary. IPv6 is always
// bracketed in host:port text, while the returned host is the unbracketed
// value Node's listen/connect APIs require.
export function parseAuthorityAddress(
  input: string,
  options: AuthorityAddressOptions
): AuthorityAddress {
  if (input.length === 0 || input !== input.trim()) {
    throw invalidAddress(options.label, input, "surrounding whitespace is not allowed");
  }

  let address = input;
  const schemeMatch = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//u.exec(address);
  if (schemeMatch) {
    const scheme = schemeMatch[1]!.toLowerCase();
    if (!options.allowedSchemes?.includes(scheme)) {
      throw invalidAddress(options.label, input, `unsupported scheme ${scheme}`);
    }
    address = address.slice(schemeMatch[0].length);
  } else if (address.includes("://")) {
    throw invalidAddress(options.label, input, "malformed scheme");
  }

  if (
    address.length === 0 ||
    /[\u0000-\u0020/\\?#@]/u.test(address)
  ) {
    throw invalidAddress(options.label, input, "userinfo, paths, queries, fragments, and whitespace are not allowed");
  }

  let host: string;
  let portText: string;
  if (address.startsWith("[")) {
    const closing = address.indexOf("]");
    if (closing <= 1 || address[closing + 1] !== ":" || address.indexOf("]", closing + 1) !== -1) {
      throw invalidAddress(options.label, input, "bracketed IPv6 must use [address]:port");
    }
    host = address.slice(1, closing);
    portText = address.slice(closing + 2);
    if (isIP(host) !== 6 || !validIPv6Zone(host)) {
      throw invalidAddress(options.label, input, "brackets may contain only a valid IPv6 address");
    }
  } else {
    const separator = address.indexOf(":");
    if (separator <= 0 || separator !== address.lastIndexOf(":")) {
      throw invalidAddress(
        options.label,
        input,
        "use host:port for DNS/IPv4 or [address]:port for IPv6"
      );
    }
    host = address.slice(0, separator);
    portText = address.slice(separator + 1);
    if (!validDNSOrIPv4(host)) {
      throw invalidAddress(options.label, input, "host is not valid DNS or IPv4");
    }
  }

  if (!/^[1-9][0-9]{0,4}$/u.test(portText)) {
    throw invalidAddress(options.label, input, "port must be canonical decimal in 1-65535");
  }
  const port = Number(portText);
  if (port > 65_535) {
    throw invalidAddress(options.label, input, "port must be in 1-65535");
  }
  return { host, port };
}

export function formatAuthorityAddress(address: AuthorityAddress): string {
  return `${isIP(address.host) === 6 ? `[${address.host}]` : address.host}:${address.port}`;
}

function validDNSOrIPv4(host: string): boolean {
  if (isIP(host) === 4) {
    return true;
  }
  // Do not let legacy resolver numeric syntaxes (or malformed IPv4) fall
  // through as DNS. Different libc implementations interpret these forms
  // differently, so they are not a stable authority identity.
  if (/^[0-9.]+$/u.test(host)) {
    return false;
  }
  if (host.length === 0 || host.length > 253 || isIP(host) !== 0) {
    return false;
  }
  return host.split(".").every(
    (label) =>
      label.length >= 1 &&
      label.length <= 63 &&
      !label.startsWith("-") &&
      !label.endsWith("-") &&
      /^[A-Za-z0-9-]+$/u.test(label)
  );
}

function validIPv6Zone(host: string): boolean {
  const percent = host.indexOf("%");
  return (
    percent === -1 ||
    (percent === host.lastIndexOf("%") &&
      percent > 0 &&
      /^[A-Za-z0-9_.-]+$/u.test(host.slice(percent + 1)))
  );
}

function invalidAddress(label: string, input: string, detail: string): Error {
  return new Error(
    `${label} must be a strict host:port address (IPv6: [address]:port); got ${JSON.stringify(input)}: ${detail}.`
  );
}
