// Compile-time product boundary: a client never shares desktop stores with the
// administrative application. Native mobile sandboxes are package/bundle scoped.
const clientOnlyBuild = bool.fromEnvironment('XIO_CLIENT_ONLY');
String desktopProductDirectory({required bool windows}) => clientOnlyBuild
    ? (windows ? 'xio-client' : 'app.xio.client')
    : (windows ? 'xio' : 'app.xio.xio');
String get credentialProductDirectory =>
    clientOnlyBuild ? 'app.xio.client' : 'app.xio.xio';
