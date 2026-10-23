// Compile-time product boundary: a client never shares desktop stores with the
// administrative application. Native mobile sandboxes are package/bundle scoped.
const clientOnlyBuild = bool.fromEnvironment('XIO_CLIENT_ONLY');
String desktopProductDirectory({required bool windows}) => clientOnlyBuild
    ? (windows ? 'xio-client' : 'app.x1o.client')
    : (windows ? 'x1o' : 'app.x1o.x1o');
String get credentialProductDirectory =>
    clientOnlyBuild ? 'app.x1o.client' : 'app.x1o.x1o';
