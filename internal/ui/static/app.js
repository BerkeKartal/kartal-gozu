// Kartal Gözü web UI: dependency-free ES modules. No framework, no build
// step, nothing fetched from the internet. API calls use relative URLs, so
// the page works under whatever path the server is published at.

import { toYAML, diffLines } from './yaml.js';
import { lineChart } from './chart.js';

const REFRESH_MS = 10000;
const FOLLOW_MS = 3000;
const METRICS_MS = 60000;
const ROW_LIMIT = 500;
const TOKEN_KEY = 'kartal.token';

const VIEWS = ['overview', 'pods', 'deployments', 'statefulsets', 'daemonsets', 'jobs', 'cronjobs', 'workloads',
  'services', 'ingresses', 'configmaps', 'secrets', 'certificates', 'volumeclaims', 'helm', 'nodes', 'namespaces', 'events',
  'alerts', 'appmetrics', 'uptime', 'changes', 'releases', 'audit', 'resources'];
// Views that are not about one namespace.
const CLUSTER_SCOPED = new Set(['nodes', 'namespaces', 'alerts', 'uptime', 'releases', 'audit']);
// Views that show every cluster at once.
const ALL_CLUSTERS = new Set(['alerts', 'releases', 'audit']);
// Views of the server itself, which checks addresses on its own.
const SERVER_VIEWS = new Set(['uptime']);
// Views whose data the agent fetches live; they reload on demand only.
const LIVE_VIEWS = new Set(['resources', 'helm']);
const WORKLOAD_KINDS = new Set(['Deployment', 'StatefulSet', 'DaemonSet']);
const KIND_VIEW = {
  Pod: 'pods', Deployment: 'deployments', StatefulSet: 'statefulsets', DaemonSet: 'daemonsets',
  Service: 'services', Ingress: 'ingresses', ConfigMap: 'configmaps', Secret: 'secrets',
  PersistentVolumeClaim: 'volumeclaims', Job: 'jobs', CronJob: 'cronjobs', Node: 'nodes',
};
// Where each built-in kind lives in the API, for object details.
const KIND_API = {
  Pod: 'core/v1/pods', Deployment: 'apps/v1/deployments', StatefulSet: 'apps/v1/statefulsets',
  DaemonSet: 'apps/v1/daemonsets', Service: 'core/v1/services', Ingress: 'networking.k8s.io/v1/ingresses',
  ConfigMap: 'core/v1/configmaps', Secret: 'core/v1/secrets', PersistentVolumeClaim: 'core/v1/persistentvolumeclaims',
  Job: 'batch/v1/jobs', CronJob: 'batch/v1/cronjobs', Node: 'core/v1/nodes', Namespace: 'core/v1/namespaces',
};
const API_KIND = Object.fromEntries(Object.entries(KIND_API).map(([k, v]) => [v, k]));
// Views that show one kind of workload out of the workloads list.
const VIEW_KIND = { deployments: 'Deployment', statefulsets: 'StatefulSet', daemonsets: 'DaemonSet' };

// NAV is the sidebar: groups of views, each with its count from the
// cluster's (or the selected namespace's) counts: [total, needs attention],
// where what needs attention may add up several counts.
const NAV = [
  { items: ['overview', 'appmetrics'] },
  { group: 'workloads', items: ['pods', 'deployments', 'statefulsets', 'daemonsets', 'jobs', 'cronjobs'] },
  { group: 'grpNetwork', items: ['services', 'ingresses'] },
  { group: 'grpConfig', items: ['configmaps', 'secrets', 'certificates'] },
  { group: 'grpStorage', items: ['volumeclaims'] },
  { group: 'grpApps', items: ['helm', 'releases'] },
  { group: 'grpCluster', items: ['nodes', 'namespaces', 'events'] },
  { group: 'grpOps', items: ['alerts', 'uptime', 'changes', 'audit'] },
  { items: ['resources'] },
];
const NAV_COUNT = {
  pods: ['pods', 'podsUnhealthy'], deployments: ['deployments', 'deploymentsDegraded'],
  statefulsets: ['statefulSets', 'statefulSetsDegraded'], daemonsets: ['daemonSets', 'daemonSetsDegraded'],
  jobs: ['jobs', 'jobsFailed'], cronjobs: ['cronJobs'], workloads: ['workloads', 'workloadsDegraded'],
  services: ['services'], ingresses: ['ingresses'], configmaps: ['configMaps'], secrets: ['secrets'],
  volumeclaims: ['volumeClaims', ['volumeClaimsUnbound', 'volumeClaimsFilling']], nodes: ['nodes', 'nodesNotReady'],
  certificates: ['certificates', 'certificatesExpiring'],
  namespaces: ['namespaces'], events: [null, 'warnings'], alerts: [null, 'alerts'],
};
const RANK = { viewer: 1, operator: 2, admin: 3 };

// ---------------------------------------------------------------- text

const STRINGS = {
  en: {
    overview: 'Overview', workloads: 'Workloads', pods: 'Pods', services: 'Services', ingresses: 'Ingresses',
    configmaps: 'ConfigMaps', secrets: 'Secrets', volumeclaims: 'Volume claims', jobs: 'Jobs',
    cronjobs: 'CronJobs', events: 'Events', nodes: 'Nodes', resources: 'All resources',
    deployments: 'Deployments', statefulsets: 'StatefulSets', daemonsets: 'DaemonSets',
    helm: 'Helm releases', alerts: 'Alerts', audit: 'Audit log',
    releases: 'Versions', changes: 'Changes', onlyDifferences: 'Only differences', 'col.app': 'App', 'col.what': 'What',
    'col.change': 'Change', 'col.by': 'By', versionsHint: 'Each app’s images in every cluster; rows whose versions differ are marked.',
    changesHint: 'What the agents saw change, and (for operators) what people changed through Kartal Gözü. Kept in memory: the last 5000.',
    noChanges2: 'No changes seen yet: the first snapshot after the server starts is only a baseline.',
    'what.created': 'created', 'what.deleted': 'deleted', 'what.image': 'new image', 'what.replicas': 'scaled',
    'what.template': 'pod template changed (a restart or a new setting)', 'what.schedule': 'new schedule', 'what.cordoned': 'cordoned',
    'what.uncordoned': 'uncordoned', 'what.ready': 'ready again', 'what.not-ready': 'not ready', 'what.suspended': 'suspended',
    'what.resumed': 'resumed', 'what.restart': 'restarted', 'what.scale': 'scaled', 'what.rollback': 'rolled back', 'what.delete': 'deleted',
    'what.cordon': 'cordoned', 'what.uncordon': 'uncordoned', 'what.suspend': 'suspended', 'what.resume': 'resumed', 'what.trigger': 'run now',
    'what.exec': 'command run', 'what.apply': 'YAML saved', 'tab.changes': 'Changes', allClusters: 'All clusters',
    drift: 'Changed since the last kubectl apply', driftNone: 'Same as the last kubectl apply.', 'col.field': 'Field',
    'col.applied': 'Applied', 'col.now': 'Now', driftHint: 'Someone changed these after the last kubectl apply (kubectl edit, scale, another tool); the next apply will set them back.',
    grpNetwork: 'Networking', grpConfig: 'Configuration', grpStorage: 'Storage', grpCluster: 'Cluster',
    grpApps: 'Applications', grpOps: 'Operations',
    chooseNamespace: 'Choose the namespace every view shows',
    pinned: 'Pinned', namespaces: 'Namespaces', namespace: 'Namespace', allNamespaces: 'All namespaces',
    filterNamespaces: 'Filter namespaces',
    pin: 'Pin to the top', unpin: 'Unpin', podsIn: 'Pods in {0}', eventsIn: 'Warning events in {0}',
    logsOf: 'Logs of {0}', unhealthyPods: '{0} unhealthy pods', noMatch: 'Nothing matches.',
    loading: 'Loading…', menu: 'Menu', search: 'Search', searchTitle: 'Jump to a namespace, view or object',
    language: 'Türkçe', theme: 'Light / dark theme', logout: 'Sign out',
    'status.online': 'Online', 'status.offline': 'Offline', 'status.never-seen': 'Never connected',
    lastSeen: 'last seen {0} ago', clusterWide: 'Cluster-wide', problemsOnly: 'Problems only',
    filterRows: 'Filter  ( / )', refresh: 'Refresh', dataFrom: 'Data from {0}', scopeTo: 'Show only {0}',
    noClusters: 'No clusters are configured. Add one with KARTAL_AGENT_TOKENS.', noItems: 'Nothing here.',
    waitingAgent: 'Waiting for this cluster’s agent',
    waitingHelp: 'No data has arrived yet. Check that kartal-agent runs in the cluster and can reach this server.',
    offlineBanner: 'The agent has been silent for {0}; this is the last data it sent.',
    failed: 'Request failed', showing: 'Showing {0} of {1}.', showMore: 'Show more',
    ready: 'ready', notReady: 'Not ready', nUnhealthy: '{0} unhealthy', allHealthy: 'all healthy',
    nDegraded: '{0} degraded', allReady: 'all ready', warnings: 'Warnings', warningEvents: 'warning events',
    cpu: 'CPU', memory: 'Memory', cores: 'cores', usedOf: '{0} of {1}', noMetrics: 'metrics-server not available',
    used: 'Used', requested: 'Requested', clusterUsage: 'Cluster usage, last hour',
    attention: 'Needs attention', allGood: 'Everything looks healthy.', recentWarnings: 'Recent warnings',
    collectionErrors: 'Could not collect', nodeNotReady: 'Node {0} is not ready', nodePressure: 'Node {0} is short of resources', replaced: 'replaced',
    replacedPods: 'Old pods left behind: {0}', replacedHint: 'Evicted or failed pods that their Deployment, StatefulSet or DaemonSet already replaced. Kubernetes keeps them until someone deletes them.',
    readyOf: '{0} of {1} ready',
    nRestarts: '{0} restarts', andMore: 'and {0} more', yes: 'yes', no: 'no', none: 'none',
    'col.name': 'Name', 'col.kind': 'Kind', 'col.namespace': 'Namespace', 'col.status': 'Status',
    'col.ready': 'Ready', 'col.restarts': 'Restarts', 'col.cpu': 'CPU', 'col.memory': 'Memory',
    'col.node': 'Node', 'col.age': 'Age', 'col.updated': 'Up to date', 'col.images': 'Images',
    'col.type': 'Type', 'col.clusterIP': 'Cluster IP', 'col.ports': 'Ports', 'col.class': 'Class',
    'col.rules': 'Rules', 'col.tls': 'TLS', 'col.capacity': 'Capacity', 'col.storageClass': 'Storage class',
    'col.access': 'Access', 'col.volume': 'Volume', 'col.completions': 'Completions', 'col.failed': 'Failed',
    'col.started': 'Started', 'col.duration': 'Duration', 'col.schedule': 'Schedule',
    'col.suspended': 'Suspended', 'col.active': 'Active', 'col.lastSchedule': 'Last run',
    'col.lastSuccess': 'Last success', 'col.lastSeen': 'Last seen', 'col.object': 'Object',
    'col.reason': 'Reason', 'col.message': 'Message', 'col.count': 'Count', 'col.roles': 'Roles',
    'col.version': 'Version', 'col.ip': 'IP', 'col.pods': 'Pods', 'col.workloads': 'Workloads', 'col.warnings': 'Warnings',
    'col.chart': 'Chart', 'col.appVersion': 'App version', 'col.revision': 'Revision', 'col.deployed': 'Deployed',
    'col.description': 'Description', 'col.time': 'Time', 'col.user': 'User', 'col.action': 'Action',
    'col.cluster': 'Cluster', 'col.result': 'Result', 'col.severity': 'Severity', 'col.problem': 'Problem',
    'col.since': 'Since', 'col.detail': 'Detail', 'col.notified': 'Notified', 'col.channel': 'Channel',
    'col.title': 'Title', 'col.source': 'Source', 'col.firstSeen': 'First seen', 'col.changeCause': 'Change cause',
    'col.replicas': 'Replicas', 'col.key': 'Key', 'col.size': 'Size', 'col.port': 'Port', 'col.target': 'Target',
    'col.nodePort': 'Node port', 'col.protocol': 'Protocol', 'col.host': 'Host', 'col.path': 'Path',
    'col.backend': 'Backend', 'col.resource': 'Resource', 'col.allocatable': 'Allocatable', 'col.requests': 'Requests',
    'col.limits': 'Limits', 'col.usage': 'Usage', 'col.image': 'Image', 'col.state': 'State',
    'col.lastTermination': 'Last termination', 'col.effect': 'Effect', 'col.value': 'Value', 'col.resources': 'Resources',
    logs: 'Logs', scale: 'Scale', restart: 'Restart', restartTitle: 'Restart workload',
    restartConfirm: 'Roll out new pods for {0}?', scaleTitle: 'Scale workload', replicas: 'Replicas',
    badReplicas: 'Replicas must be a whole number, 0 or more.', cancel: 'Cancel', done: 'Done',
    container: 'Container', lastN: 'last {0} lines', follow: 'Follow', wrap: 'Wrap', download: 'Download',
    close: 'Close', noLogs: 'No log lines.', clusterScoped: 'cluster-scoped',
    discoveryErrors: 'Some API groups did not answer', allTypes: 'All types',
    paletteHint: 'Jump to a namespace, view or object…', paletteKeys: '↑ ↓ move · Enter open · Esc close',
    view: 'View', cluster: 'Cluster', action: 'Action', toggleTheme: 'Switch light / dark theme',
    token: 'Access token', tokenHelp: 'Your token for this server (KARTAL_USERS or KARTAL_ADMIN_TOKEN). It stays in this browser.',
    remember: 'Remember on this device', signIn: 'Sign in', badToken: 'That token was not accepted.',
    userName: 'User name', password: 'Password', passwordHelp: 'The account you sign in to your computer with.',
    useToken: 'Sign in with an access token instead', usePassword: 'Sign in with your user name and password',
    sessionEnded: 'Your session has ended; please sign in again.',
    details: 'Details', copy: 'Copy', copied: 'Copied.', edit: 'Edit', preview: 'Preview changes', save: 'Save',
    editHint: 'Edit the YAML, preview what the API server would store, then save. A newer version of the object is never overwritten.',
    secretNoEdit: 'Secrets cannot be edited here: their values are never shown.', noChanges: 'No changes.',
    saved: 'Saved.', diffTooBig: 'Too many changes to show line by line.', unchanged: '{0} unchanged lines',
    previewFirst: 'Preview the changes first.', resize: 'Drag to resize', gone: 'Could not reload: {0}',
    discardTitle: 'Discard your changes?', discardConfirm: 'The YAML you edited has not been saved.', discard: 'Discard',
    'tab.summary': 'Summary', 'tab.yaml': 'YAML', 'tab.events': 'Events', 'tab.pods': 'Pods', 'tab.logs': 'Logs',
    'tab.history': 'History', 'tab.metrics': 'Metrics', 'tab.console': 'Console', 'tab.jobs': 'Jobs',
    'f.created': 'Created', 'f.labels': 'Labels', 'f.annotations': 'Annotations', 'f.owner': 'Controlled by',
    'f.node': 'Node', 'f.podIP': 'Pod IP', 'f.qos': 'QoS class', 'f.serviceAccount': 'Service account',
    'f.restartPolicy': 'Restart policy', 'f.priority': 'Priority class', 'f.started': 'Started',
    'f.replicas': 'Replicas', 'f.strategy': 'Update strategy', 'f.selector': 'Selector', 'f.revision': 'Revision',
    'f.conditions': 'Conditions', 'f.containers': 'Containers', 'f.initContainers': 'Init containers',
    'f.type': 'Type', 'f.clusterIP': 'Cluster IP', 'f.externalIPs': 'External IPs', 'f.ports': 'Ports',
    'f.sessionAffinity': 'Session affinity', 'f.class': 'Class', 'f.tls': 'TLS hosts', 'f.rules': 'Rules',
    'f.data': 'Data', 'f.keys': 'Keys', 'f.schedule': 'Schedule', 'f.timeZone': 'Time zone', 'f.suspend': 'Suspended',
    'f.concurrency': 'Concurrency', 'f.lastSchedule': 'Last run', 'f.lastSuccess': 'Last success',
    'f.completions': 'Completions', 'f.parallelism': 'Parallelism', 'f.backoffLimit': 'Retries',
    'f.succeeded': 'Succeeded', 'f.failed': 'Failed', 'f.active': 'Active', 'f.completed': 'Completed',
    'f.duration': 'Duration', 'f.capacity': 'Resources', 'f.taints': 'Taints', 'f.addresses': 'Addresses',
    'f.os': 'OS image', 'f.kernel': 'Kernel', 'f.runtime': 'Container runtime', 'f.kubelet': 'Kubelet',
    'f.unschedulable': 'Unschedulable', 'f.phase': 'Phase', 'f.storage': 'Storage', 'f.requestedStorage': 'Requested',
    'f.accessModes': 'Access modes', 'f.volume': 'Volume', 'f.volumeMode': 'Volume mode', 'f.status': 'Status',
    'f.seeYaml': 'This kind has no summary of its own; the YAML tab shows everything.', 'f.showAll': 'show all',
    hidden: 'hidden', running: 'running', waiting: 'waiting', terminated: 'terminated',
    previous: 'Previous container', allContainers: 'All containers', timestamps: 'Timestamps',
    onlyMatches: 'Only matching lines', searchLogs: 'Search the logs', noMatches: 'no match',
    restartedHint: 'This container restarted {0} times; the previous instance’s logs usually show why.',
    showPrevious: 'Show the previous logs',
    consoleHint: 'Each command runs on its own, without a terminal, so vi or top do not work. The working directory is kept.',
    run: 'Run', clear: 'Clear', exitCode: 'exit code {0}', truncated: 'output cut short',
    noShell: 'This image has no sh, so commands cannot run in it.',
    revision: 'Revision', current: 'current', rollbackTo: 'Roll back', rollbackTitle: 'Roll back',
    rollbackConfirm: 'Roll {0} back to revision {1}? A new rollout starts.',
    last1h: '1 hour', last6h: '6 hours',
    noHistory: 'No history yet: a point is added every minute while metrics-server reports.',
    request: 'request', limit: 'limit', allocatable: 'allocatable',
    deletePod: 'Delete', deleteTitle: 'Delete pod', deleteConfirm: 'Delete pod {0}? Its controller starts a replacement.',
    cordon: 'Cordon', uncordon: 'Uncordon', cordonTitle: 'Cordon node',
    cordonConfirm: 'Stop scheduling new pods on {0}? Running pods stay.', uncordonConfirm: 'Allow new pods on {0} again?',
    runNow: 'Run now', runNowTitle: 'Run CronJob', runNowConfirm: 'Start a Job from {0} now?',
    suspend: 'Suspend', resume: 'Resume', suspendConfirm: 'Stop scheduling {0}?', resumeConfirm: 'Resume scheduling {0}?',
    'capMissing.write': 'This cluster’s agent does not allow changes (KARTAL_ALLOW_WRITE=false).',
    'capMissing.exec': 'This cluster’s agent does not run commands (KARTAL_ALLOW_EXEC=false).',
    'capMissing.edit': 'This cluster’s agent does not edit objects (KARTAL_ALLOW_EDIT=false).',
    'role.viewer': 'viewer', 'role.operator': 'operator', 'role.admin': 'admin',
    alertsActive: 'Active problems', alertsRecent: 'Recent', alertsChannels: 'Notification channels',
    noChannels: 'No channel is set up yet. Admins can set up e-mail here; Teams and webhooks are set on the server (KARTAL_ALERT_TEAMS_URL, KARTAL_ALERT_WEBHOOK_URL).',
    alertsOff: 'Alerts are off on this server.', testNotify: 'Send a test', testSent: 'Test sent: {0}',
    mailSettings: 'E-mail settings', mailEnabled: 'Send alerts by e-mail', mailServer: 'SMTP server',
    mailServerHelp: 'host:port. Port 587 uses STARTTLS, 465 uses TLS from the start.', mailFrom: 'Sender', mailTo: 'Recipients',
    mailToHelp: 'Separate addresses with commas.', mailUser: 'User name (if the server needs one)', mailPassword: 'Password',
    mailPasswordKeep: 'A password is saved; leave this empty to keep it.', mailPasswordClear: 'Remove the saved password',
    mailFixed: 'These settings come from the server’s environment (KARTAL_SMTP_*) and can only be changed there.',
    mailWhere: 'Kept in {0}.', mailNotKept: 'This server keeps these settings only until it restarts. To keep them, set KARTAL_SETTINGS_SECRET or KARTAL_SETTINGS_FILE.',
    mailLoadError: 'The saved settings could not be read: {0}', mailSaved: 'E-mail settings saved.', sending: 'Sending…',
    sendTest: 'Send a test e-mail',
    notified: 'notified', waitingNotify: 'waiting', noAlerts: 'No active problems.',
    alertsAfter: 'A problem is notified once it has lasted {0}; problems that start or end together go out as one message.',
    deliveries: 'Last deliveries', resolvedAt: 'resolved', startedAt: 'started',
    'alert.AgentOffline': 'Agent offline', 'alert.NodeNotReady': 'Node not ready', 'alert.NodePressure': 'Node under pressure', 'alert.PodFailing': 'Pod failing',
    'alert.WorkloadDegraded': 'Workload degraded', 'alert.JobFailed': 'Job failed', 'alert.VolumeClaimUnbound': 'Volume claim unbound',
    'alert.VolumeFilling': 'Volume filling up', 'alert.CertificateExpiring': 'Certificate expiring', 'alert.URLDown': 'Address not answering',
    'alert.MetricLimit': 'Metric past its limit',
    appmetrics: 'Metrics', 'tab.scrape': 'App metrics', 'capMissing.scrape': 'This cluster’s agent does not read the metrics of pods (KARTAL_POD_METRICS=false).',
    scrapeHint: 'Applications often expose metrics of their own, such as requests, errors or queue lengths, at an address like :9100/metrics. Choose the port and read them.',
    readMetrics: 'Read', port: 'Port', path: 'Path', metricsFilter: 'Filter metrics', nSeries: '{0} series', moreSeries: '… and {0} more series',
    truncatedMetrics: 'The pod exposes more than is shown here.', noMetricsHere: 'The pod exposed no metrics.', moreMetrics: 'Show {0} more metrics',
    watch: 'Watch', watchTitle: 'Watch a metric', editWatch: 'Change the watch', watchTarget: 'Pods', allPodsOf: 'Every pod of {0}',
    onlyThisPod: 'Only this pod ({0})', watchSeries: 'Series', allSeries: '{0}: all series', watchMetric: 'Metric', watchLabels: 'Labels',
    watchLabelsHelp: 'Only the series with these labels, such as code=500. Empty: all of them.', watchRate: 'How fast it grows, per second (for counters)',
    watchAggregate: 'Joined over the pods as', 'agg.sum': 'sum', 'agg.avg': 'average', 'agg.max': 'maximum', 'agg.min': 'minimum',
    watchAbove: 'Alert above', watchBelow: 'Alert below', watchLimitHelp: 'Optional: an alert is raised while the value is past it.',
    watchSaved: 'Watch saved; its chart is under Metrics.', watchRemoved: 'Watch removed.', removeWatch: 'Remove',
    removeWatchTitle: 'Remove watch', removeWatchConfirm: 'Stop watching {0}? Its history is lost.', badLabels: 'Write labels as name=value, separated by commas.',
    watchesHint: 'The server reads these metrics from the pods every 30 seconds and keeps a day of them in memory. To add one, open a pod or a workload and choose its App metrics tab.',
    noWatches: 'Nothing is watched yet. Start with “Find what exposes metrics” above, or open a workload and choose its App metrics tab; what you Watch shows here.', noRunningPod: 'None of its pods is running, so there is nothing to read.', noPointsYet: 'Waiting for the first readings.',
    last24h: '24 hours', perSecond: 'per second', limitAbove: 'Limit', limitBelow: 'Lower limit', podsRead: '{0} pods',
    findSources: 'Find what exposes metrics', findingSources: 'Asking one pod of each workload for its metrics…', sourcesTitle: 'Exposing metrics: {0}',
    sourcesHint: 'One running pod of each workload was asked at its likely ports, leaving out those of databases and other servers that do not speak HTTP. Open one to see its metrics, and Watch any of them to chart it here.',
    noSources: 'None of the {0} workloads asked answered with metrics.', sourcesUnfinished: 'Time ran out before every workload was asked; choose a namespace to look closer.',
    openMetrics: 'Show metrics', 'col.address': 'Address', 'col.metrics': 'Metrics', 'col.workload': 'Workload',
    certificates: 'Certificates', uptime: 'URL checks', fromServer: 'Checked from the Kartal Gözü server',
    'col.subject': 'Subject', 'col.issuer': 'Issuer', 'col.expires': 'Expires', 'col.used': 'Used', 'col.check': 'Check',
    'col.last24h': 'Last 24 hours', 'col.uptime': 'Uptime', 'col.response': 'Response', 'col.certificate': 'Certificate',
    expiresIn: 'in {0}', expiredAgo: 'expired {0} ago', inodesUsed: 'inodes: {0}% used',
    volumeUseHint: 'Not known. The agent asks the kubelets when KARTAL_VOLUME_STATS is on (rbac-volumes.yaml), for volumes that a running pod mounts.',
    certificatesHint: 'From the tls.crt of kubernetes.io/tls Secrets, when KARTAL_TLS_SECRETS is on for the agent (rbac-certificates.yaml); keys are never read. Marked when they expire within {0} days.',
    checksHint: 'The server requests each address on its own and keeps 24 hours of results in memory. A failing check, or a certificate that expires soon, raises an alert.',
    noChecks: 'No URL checks yet.', addCheck: 'Add a check', removeCheck: 'Remove', removeCheckTitle: 'Remove the check',
    removeCheckConfirm: 'Remove the check {0}? Its results go with it.', checkSaved: 'Check saved.', checkRemoved: 'Check removed.',
    'check.up': 'Up', 'check.down': 'Down', 'check.waiting': 'Waiting', upFor: 'for {0}', checkName: 'Name',
    checkURL: 'Address', checkURLHelp: 'http or https; without either, https is used. The server itself asks the address, so it must be reachable from there.',
    checkInterval: 'Every', checkTimeout: 'Timeout (seconds)', checkStatus: 'Expected status', checkStatusHelp: 'Empty: any status below 400.',
    checkContains: 'The answer must contain', checkInsecure: 'Do not verify the certificate (its expiry is still watched)',
    tryCheck: 'Try now', trying: 'Asking…', tryOK: '✓ answered {0} in {1} ms', certUntil: 'certificate until {0}',
    hourFailed: '{0}: {1} of {2} failed', hourNone: '{0}: no results', newCheck: 'New URL check', editCheck: 'URL check',
    critical: 'critical', warning: 'warning',
    auditEmpty: 'Nothing has been changed through Kartal Gözü yet.',
    auditHint: 'The last 1000 changes, kept in memory; the server log keeps all of them.', ok: 'ok',
  },
  tr: {
    overview: 'Genel bakış', workloads: 'İş yükleri', pods: 'Podlar', services: 'Servisler',
    ingresses: 'Ingress’ler', configmaps: 'ConfigMap’ler', secrets: 'Secret’lar', volumeclaims: 'PVC’ler',
    jobs: 'Job’lar', cronjobs: 'CronJob’lar', events: 'Olaylar', nodes: 'Node’lar', resources: 'Tüm kaynaklar',
    deployments: 'Deployment’lar', statefulsets: 'StatefulSet’ler', daemonsets: 'DaemonSet’ler',
    helm: 'Helm release’leri', alerts: 'Uyarılar', audit: 'Denetim kaydı',
    releases: 'Sürümler', changes: 'Değişiklikler', onlyDifferences: 'Sadece farklar', 'col.app': 'Uygulama', 'col.what': 'Ne',
    'col.change': 'Değişiklik', 'col.by': 'Yapan', versionsHint: 'Her uygulamanın imajları, her cluster’da; sürümleri farklı olan satırlar işaretlenir.',
    changesHint: 'Agent’ların gördüğü değişiklikler ve (operatörler için) Kartal Gözü’nden yapılanlar. Bellekte tutulur: son 5000.',
    noChanges2: 'Henüz değişiklik görülmedi: sunucu açıldıktan sonraki ilk snapshot yalnızca başlangıç noktasıdır.',
    'what.created': 'oluşturuldu', 'what.deleted': 'silindi', 'what.image': 'yeni imaj', 'what.replicas': 'ölçeklendi',
    'what.template': 'pod şablonu değişti (yeniden başlatma ya da yeni ayar)', 'what.schedule': 'yeni zamanlama', 'what.cordoned': 'cordon edildi',
    'what.uncordoned': 'uncordon edildi', 'what.ready': 'yeniden hazır', 'what.not-ready': 'hazır değil', 'what.suspended': 'askıya alındı',
    'what.resumed': 'devam ettirildi', 'what.restart': 'yeniden başlatıldı', 'what.scale': 'ölçeklendi', 'what.rollback': 'geri alındı', 'what.delete': 'silindi',
    'what.cordon': 'cordon edildi', 'what.uncordon': 'uncordon edildi', 'what.suspend': 'askıya alındı', 'what.resume': 'devam ettirildi',
    'what.trigger': 'hemen çalıştırıldı', 'what.exec': 'komut çalıştırıldı', 'what.apply': 'YAML kaydedildi', 'tab.changes': 'Değişiklikler', allClusters: 'Tüm cluster’lar',
    drift: 'Son kubectl apply’dan beri değişenler', driftNone: 'Son kubectl apply ile aynı.', 'col.field': 'Alan',
    'col.applied': 'Uygulanan', 'col.now': 'Şu an', driftHint: 'Bunlar son kubectl apply’dan sonra değişti (kubectl edit, scale, başka bir araç); bir sonraki apply onları geri alır.',
    grpNetwork: 'Ağ', grpConfig: 'Yapılandırma', grpStorage: 'Depolama', grpCluster: 'Cluster',
    grpApps: 'Uygulamalar', grpOps: 'Operasyon',
    chooseNamespace: 'Tüm görünümlerin gösterdiği namespace’i seç',
    pinned: 'Sabitlenenler', namespaces: 'Namespace’ler', namespace: 'Namespace',
    allNamespaces: 'Tüm namespace’ler', filterNamespaces: 'Namespace ara',
    pin: 'Üste sabitle', unpin: 'Sabitlemeyi kaldır', podsIn: '{0} içindeki podlar',
    eventsIn: '{0} içindeki uyarı olayları', logsOf: '{0} logları', unhealthyPods: '{0} sorunlu pod',
    noMatch: 'Eşleşen bir şey yok.', loading: 'Yükleniyor…', menu: 'Menü', search: 'Ara',
    searchTitle: 'Namespace, görünüm ya da nesneye git', language: 'English', theme: 'Açık / koyu tema',
    logout: 'Çıkış yap', 'status.online': 'Bağlı', 'status.offline': 'Bağlantı yok',
    'status.never-seen': 'Hiç bağlanmadı', lastSeen: 'son görülme {0} önce', clusterWide: 'Cluster geneli',
    problemsOnly: 'Sadece sorunlular', filterRows: 'Filtrele  ( / )', refresh: 'Yenile', dataFrom: 'Veri: {0}',
    scopeTo: 'Sadece {0} göster',
    noClusters: 'Tanımlı cluster yok. KARTAL_AGENT_TOKENS ile ekleyin.', noItems: 'Burada bir şey yok.',
    waitingAgent: 'Bu cluster’ın agent’ı bekleniyor',
    waitingHelp: 'Henüz veri gelmedi. kartal-agent’ın cluster’da çalıştığını ve bu sunucuya erişebildiğini kontrol edin.',
    offlineBanner: 'Agent {0} süredir sessiz; gösterilen, gönderdiği son veri.',
    failed: 'İstek başarısız', showing: '{1} kayıttan {0} tanesi gösteriliyor.', showMore: 'Daha fazla göster',
    ready: 'hazır', notReady: 'Hazır değil', nUnhealthy: '{0} sorunlu', allHealthy: 'hepsi sağlıklı',
    nDegraded: '{0} eksik', allReady: 'hepsi hazır', warnings: 'Uyarılar', warningEvents: 'uyarı olayı',
    cpu: 'CPU', memory: 'Bellek', cores: 'çekirdek', usedOf: '{0} / {1}', noMetrics: 'metrics-server yok',
    used: 'Kullanılan', requested: 'Ayrılan', clusterUsage: 'Cluster kullanımı, son bir saat',
    attention: 'İlgilenilmesi gerekenler', allGood: 'Her şey sağlıklı görünüyor.', recentWarnings: 'Son uyarılar',
    collectionErrors: 'Toplanamayanlar', nodeNotReady: '{0} node’u hazır değil', nodePressure: '{0} node’unda kaynak sıkıntısı', replaced: 'yenisi açıldı',
    replacedPods: 'Geride kalan eski pod: {0}', replacedHint: 'Deployment, StatefulSet ya da DaemonSet’in yerine yenisini açtığı, evict edilmiş ya da düşmüş podlar. Kubernetes bunları biri silene kadar tutar.',
    readyOf: '{1} replikadan {0} hazır',
    nRestarts: '{0} yeniden başlama', andMore: 've {0} tane daha', yes: 'evet', no: 'hayır', none: 'yok',
    'col.name': 'Ad', 'col.kind': 'Tür', 'col.namespace': 'Namespace', 'col.status': 'Durum',
    'col.ready': 'Hazır', 'col.restarts': 'Yeniden başlama', 'col.cpu': 'CPU', 'col.memory': 'Bellek',
    'col.node': 'Node', 'col.age': 'Yaş', 'col.updated': 'Güncel', 'col.images': 'İmajlar', 'col.type': 'Tip',
    'col.clusterIP': 'Cluster IP', 'col.ports': 'Portlar', 'col.class': 'Sınıf', 'col.rules': 'Kurallar',
    'col.tls': 'TLS', 'col.capacity': 'Kapasite', 'col.storageClass': 'Storage class', 'col.access': 'Erişim',
    'col.volume': 'Volume', 'col.completions': 'Tamamlanan', 'col.failed': 'Başarısız', 'col.started': 'Başlangıç',
    'col.duration': 'Süre', 'col.schedule': 'Zamanlama', 'col.suspended': 'Askıda', 'col.active': 'Aktif',
    'col.lastSchedule': 'Son çalışma', 'col.lastSuccess': 'Son başarılı', 'col.lastSeen': 'Son görülme',
    'col.object': 'Nesne', 'col.reason': 'Neden', 'col.message': 'Mesaj', 'col.count': 'Adet',
    'col.roles': 'Roller', 'col.version': 'Sürüm', 'col.ip': 'IP', 'col.pods': 'Pod', 'col.workloads': 'İş yükü',
    'col.warnings': 'Uyarı', 'col.chart': 'Chart', 'col.appVersion': 'Uygulama sürümü', 'col.revision': 'Revizyon',
    'col.deployed': 'Yüklenme', 'col.description': 'Açıklama', 'col.time': 'Zaman', 'col.user': 'Kullanıcı',
    'col.action': 'İşlem', 'col.cluster': 'Cluster', 'col.result': 'Sonuç', 'col.severity': 'Önem',
    'col.problem': 'Sorun', 'col.since': 'Başlangıç', 'col.detail': 'Ayrıntı', 'col.notified': 'Bildirim',
    'col.channel': 'Kanal', 'col.title': 'Başlık', 'col.source': 'Kaynak', 'col.firstSeen': 'İlk görülme',
    'col.changeCause': 'Değişiklik nedeni', 'col.replicas': 'Replika', 'col.key': 'Anahtar', 'col.size': 'Boyut',
    'col.port': 'Port', 'col.target': 'Hedef', 'col.nodePort': 'Node portu', 'col.protocol': 'Protokol',
    'col.host': 'Host', 'col.path': 'Yol', 'col.backend': 'Backend', 'col.resource': 'Kaynak',
    'col.allocatable': 'Ayrılabilir', 'col.requests': 'İstek', 'col.limits': 'Limit', 'col.usage': 'Kullanım',
    'col.image': 'İmaj', 'col.state': 'Durum', 'col.lastTermination': 'Son sonlanma', 'col.effect': 'Etki',
    'col.value': 'Değer', 'col.resources': 'Kaynaklar',
    logs: 'Loglar', scale: 'Ölçekle', restart: 'Yeniden başlat', restartTitle: 'İş yükünü yeniden başlat',
    restartConfirm: '{0} için yeni podlar başlatılsın mı?', scaleTitle: 'İş yükünü ölçekle', replicas: 'Replika',
    badReplicas: 'Replika sayısı 0 ya da daha büyük bir tam sayı olmalı.', cancel: 'Vazgeç', done: 'Tamam',
    container: 'Container', lastN: 'son {0} satır', follow: 'Canlı takip', wrap: 'Satır kaydır',
    download: 'İndir', close: 'Kapat', noLogs: 'Log satırı yok.', clusterScoped: 'cluster geneli',
    discoveryErrors: 'Bazı API grupları cevap vermedi', allTypes: 'Tüm türler',
    paletteHint: 'Namespace, görünüm ya da nesneye git…', paletteKeys: '↑ ↓ gez · Enter aç · Esc kapat',
    view: 'Görünüm', cluster: 'Cluster', action: 'İşlem', toggleTheme: 'Açık / koyu temaya geç',
    token: 'Erişim anahtarı', tokenHelp: 'Bu sunucu için anahtarın (KARTAL_USERS ya da KARTAL_ADMIN_TOKEN). Yalnızca bu tarayıcıda kalır.',
    remember: 'Bu cihazda hatırla', signIn: 'Giriş yap', badToken: 'Bu anahtar kabul edilmedi.',
    userName: 'Kullanıcı adı', password: 'Şifre', passwordHelp: 'Bilgisayarınıza girdiğiniz kurum hesabı.',
    useToken: 'Bunun yerine erişim anahtarıyla gir', usePassword: 'Kullanıcı adı ve şifreyle gir',
    sessionEnded: 'Oturumunuz sona erdi; lütfen yeniden giriş yapın.',
    details: 'Detay', copy: 'Kopyala', copied: 'Kopyalandı.', edit: 'Düzenle', preview: 'Değişiklikleri önizle', save: 'Kaydet',
    editHint: 'YAML’ı düzenle, API sunucusunun ne kaydedeceğini önizle, sonra kaydet. Nesnenin daha yeni bir sürümünün üstüne asla yazılmaz.',
    secretNoEdit: 'Secret’lar burada düzenlenemez: değerleri hiç gösterilmez.', noChanges: 'Değişiklik yok.',
    saved: 'Kaydedildi.', diffTooBig: 'Satır satır gösterilemeyecek kadar çok değişiklik var.', unchanged: '{0} satır değişmedi',
    previewFirst: 'Önce değişiklikleri önizle.', resize: 'Boyutlandırmak için sürükle', gone: 'Yenilenemedi: {0}',
    discardTitle: 'Değişiklikler atılsın mı?', discardConfirm: 'Düzenlediğin YAML kaydedilmedi.', discard: 'At',
    'tab.summary': 'Özet', 'tab.yaml': 'YAML', 'tab.events': 'Olaylar', 'tab.pods': 'Podlar', 'tab.logs': 'Loglar',
    'tab.history': 'Geçmiş', 'tab.metrics': 'Grafik', 'tab.console': 'Konsol', 'tab.jobs': 'Job’lar',
    'f.created': 'Oluşturulma', 'f.labels': 'Etiketler', 'f.annotations': 'Açıklamalar (annotation)', 'f.owner': 'Yöneten',
    'f.node': 'Node', 'f.podIP': 'Pod IP', 'f.qos': 'QoS sınıfı', 'f.serviceAccount': 'Service account',
    'f.restartPolicy': 'Yeniden başlatma', 'f.priority': 'Öncelik sınıfı', 'f.started': 'Başlama',
    'f.replicas': 'Replika', 'f.strategy': 'Güncelleme stratejisi', 'f.selector': 'Seçici', 'f.revision': 'Revizyon',
    'f.conditions': 'Koşullar', 'f.containers': 'Container’lar', 'f.initContainers': 'Init container’lar',
    'f.type': 'Tip', 'f.clusterIP': 'Cluster IP', 'f.externalIPs': 'Dış IP’ler', 'f.ports': 'Portlar',
    'f.sessionAffinity': 'Oturum yakınlığı', 'f.class': 'Sınıf', 'f.tls': 'TLS host’ları', 'f.rules': 'Kurallar',
    'f.data': 'Veri', 'f.keys': 'Anahtarlar', 'f.schedule': 'Zamanlama', 'f.timeZone': 'Saat dilimi', 'f.suspend': 'Askıda',
    'f.concurrency': 'Eşzamanlılık', 'f.lastSchedule': 'Son çalışma', 'f.lastSuccess': 'Son başarılı',
    'f.completions': 'Tamamlanma', 'f.parallelism': 'Paralellik', 'f.backoffLimit': 'Tekrar sınırı',
    'f.succeeded': 'Başarılı', 'f.failed': 'Başarısız', 'f.active': 'Aktif', 'f.completed': 'Bitiş',
    'f.duration': 'Süre', 'f.capacity': 'Kaynaklar', 'f.taints': 'Taint’ler', 'f.addresses': 'Adresler',
    'f.os': 'İşletim sistemi', 'f.kernel': 'Çekirdek', 'f.runtime': 'Container runtime', 'f.kubelet': 'Kubelet',
    'f.unschedulable': 'Zamanlanamaz', 'f.phase': 'Durum', 'f.storage': 'Depolama', 'f.requestedStorage': 'İstenen',
    'f.accessModes': 'Erişim', 'f.volume': 'Volume', 'f.volumeMode': 'Volume modu', 'f.status': 'Durum',
    'f.seeYaml': 'Bu türün kendi özeti yok; YAML sekmesi her şeyi gösterir.', 'f.showAll': 'tümünü göster',
    hidden: 'gizli', running: 'çalışıyor', waiting: 'bekliyor', terminated: 'sonlandı',
    previous: 'Önceki container', allContainers: 'Tüm container’lar', timestamps: 'Zaman damgası',
    onlyMatches: 'Sadece eşleşenler', searchLogs: 'Loglarda ara', noMatches: 'eşleşme yok',
    restartedHint: 'Bu container {0} kez yeniden başladı; nedeni genellikle önceki instance’ın loglarında görünür.',
    showPrevious: 'Önceki logları göster',
    consoleHint: 'Her komut kendi başına, terminal olmadan çalışır; bu yüzden vi ya da top çalışmaz. Çalışma dizini korunur.',
    run: 'Çalıştır', clear: 'Temizle', exitCode: 'çıkış kodu {0}', truncated: 'çıktı kısaltıldı',
    noShell: 'Bu imajda sh yok; içinde komut çalıştırılamaz.',
    revision: 'Revizyon', current: 'şu anki', rollbackTo: 'Geri dön', rollbackTitle: 'Geri al',
    rollbackConfirm: '{0}, {1}. revizyona geri alınsın mı? Yeni bir rollout başlar.',
    last1h: '1 saat', last6h: '6 saat',
    noHistory: 'Henüz geçmiş yok: metrics-server veri verdikçe her dakika bir nokta eklenir.',
    request: 'istek', limit: 'limit', allocatable: 'ayrılabilir',
    deletePod: 'Sil', deleteTitle: 'Pod’u sil', deleteConfirm: '{0} silinsin mi? Yöneten controller yerine yenisini başlatır.',
    cordon: 'Cordon', uncordon: 'Uncordon', cordonTitle: 'Node’u cordon et',
    cordonConfirm: '{0} üzerine yeni pod yerleştirilmesi durdurulsun mu? Çalışan podlar kalır.',
    uncordonConfirm: '{0} üzerine yeniden pod yerleştirilsin mi?',
    runNow: 'Şimdi çalıştır', runNowTitle: 'CronJob’u çalıştır', runNowConfirm: '{0} için şimdi bir Job başlatılsın mı?',
    suspend: 'Askıya al', resume: 'Devam ettir', suspendConfirm: '{0} zamanlaması durdurulsun mu?',
    resumeConfirm: '{0} zamanlaması devam etsin mi?',
    'capMissing.write': 'Bu cluster’ın agent’ı değişikliğe izin vermiyor (KARTAL_ALLOW_WRITE=false).',
    'capMissing.exec': 'Bu cluster’ın agent’ı komut çalıştırmıyor (KARTAL_ALLOW_EXEC=false).',
    'capMissing.edit': 'Bu cluster’ın agent’ı nesne düzenlemiyor (KARTAL_ALLOW_EDIT=false).',
    'role.viewer': 'izleyici', 'role.operator': 'operatör', 'role.admin': 'yönetici',
    alertsActive: 'Aktif sorunlar', alertsRecent: 'Son değişiklikler', alertsChannels: 'Bildirim kanalları',
    noChannels: 'Henüz kanal ayarlanmamış. Yöneticiler e-postayı buradan ayarlayabilir; Teams ve webhook sunucuda ayarlanır (KARTAL_ALERT_TEAMS_URL, KARTAL_ALERT_WEBHOOK_URL).',
    alertsOff: 'Bu sunucuda uyarılar kapalı.', testNotify: 'Test bildirimi gönder', testSent: 'Test gönderildi: {0}',
    mailSettings: 'E-posta ayarları', mailEnabled: 'Uyarıları e-postayla gönder', mailServer: 'SMTP sunucusu',
    mailServerHelp: 'host:port. 587 portu STARTTLS, 465 portu baştan TLS kullanır.', mailFrom: 'Gönderen', mailTo: 'Alıcılar',
    mailToHelp: 'Adresleri virgülle ayırın.', mailUser: 'Kullanıcı adı (sunucu istiyorsa)', mailPassword: 'Şifre',
    mailPasswordKeep: 'Kayıtlı bir şifre var; korumak için boş bırakın.', mailPasswordClear: 'Kayıtlı şifreyi kaldır',
    mailFixed: 'Bu ayarlar sunucunun ortam değişkenlerinden (KARTAL_SMTP_*) geliyor; yalnızca orada değiştirilebilir.',
    mailWhere: '{0} içinde saklanır.', mailNotKept: 'Bu sunucu ayarları yalnızca yeniden başlayana kadar tutar. Kalıcı olması için KARTAL_SETTINGS_SECRET ya da KARTAL_SETTINGS_FILE ayarlayın.',
    mailLoadError: 'Kayıtlı ayarlar okunamadı: {0}', mailSaved: 'E-posta ayarları kaydedildi.', sending: 'Gönderiliyor…',
    sendTest: 'Test e-postası gönder',
    notified: 'bildirildi', waitingNotify: 'bekliyor', noAlerts: 'Aktif sorun yok.',
    alertsAfter: 'Bir sorun {0} sürerse bildirilir; birlikte başlayan ya da biten sorunlar tek mesajda gider.',
    deliveries: 'Son gönderimler', resolvedAt: 'çözüldü', startedAt: 'başladı',
    'alert.AgentOffline': 'Agent çevrimdışı', 'alert.NodeNotReady': 'Node hazır değil', 'alert.NodePressure': 'Node’da kaynak sıkıntısı', 'alert.PodFailing': 'Pod hata veriyor',
    'alert.WorkloadDegraded': 'İş yükü eksik', 'alert.JobFailed': 'Job başarısız', 'alert.VolumeClaimUnbound': 'PVC bağlanmadı',
    'alert.VolumeFilling': 'Disk doluyor', 'alert.CertificateExpiring': 'Sertifikanın süresi doluyor', 'alert.URLDown': 'Adres cevap vermiyor',
    'alert.MetricLimit': 'Metrik sınırı aştı',
    appmetrics: 'Metrikler', 'tab.scrape': 'Metrikler', 'capMissing.scrape': 'Bu cluster’ın agent’ı podların metriklerini okumuyor (KARTAL_POD_METRICS=false).',
    scrapeHint: 'Uygulamalar çoğu zaman istek, hata ya da kuyruk uzunluğu gibi kendi metriklerini :9100/metrics gibi bir adreste yayınlar. Portu seçip okuyun.',
    readMetrics: 'Oku', port: 'Port', path: 'Yol', metricsFilter: 'Metriklerde ara', nSeries: '{0} seri', moreSeries: '… ve {0} seri daha',
    truncatedMetrics: 'Pod burada gösterilenden fazlasını yayınlıyor.', noMetricsHere: 'Pod hiç metrik yayınlamadı.', moreMetrics: '{0} metrik daha göster',
    watch: 'İzle', watchTitle: 'Metriği izle', editWatch: 'İzlemeyi değiştir', watchTarget: 'Podlar', allPodsOf: '{0} altındaki tüm podlar',
    onlyThisPod: 'Yalnızca bu pod ({0})', watchSeries: 'Seri', allSeries: '{0}: tüm seriler', watchMetric: 'Metrik', watchLabels: 'Etiketler',
    watchLabelsHelp: 'Yalnızca bu etiketlere sahip seriler, örneğin code=500. Boş bırakılırsa hepsi.', watchRate: 'Saniyedeki artışı göster (sayaçlar için)',
    watchAggregate: 'Podlar üzerinden birleştirme', 'agg.sum': 'toplam', 'agg.avg': 'ortalama', 'agg.max': 'en yüksek', 'agg.min': 'en düşük',
    watchAbove: 'Şunun üstünde uyar', watchBelow: 'Şunun altında uyar', watchLimitHelp: 'İsteğe bağlı: değer bu sınırı geçtiği sürece uyarı verilir.',
    watchSaved: 'İzleme kaydedildi; grafiği Metrikler sayfasında.', watchRemoved: 'İzleme kaldırıldı.', removeWatch: 'Kaldır',
    removeWatchTitle: 'İzlemeyi kaldır', removeWatchConfirm: '{0} artık izlenmesin mi? Geçmişi silinir.', badLabels: 'Etiketleri virgülle ayrılmış ad=değer olarak yazın.',
    watchesHint: 'Sunucu bu metrikleri 30 saniyede bir podlardan okur ve bir günlüğünü bellekte tutar. Eklemek için bir pod ya da iş yükü açıp Metrikler sekmesine geçin.',
    noWatches: 'Henüz izlenen metrik yok. Yukarıdaki “Metrik yayınlayanları bul” ile başlayın ya da bir iş yükü açıp Metrikler sekmesine geçin; İzle ile eklediğiniz metrikler burada görünür.', noRunningPod: 'Çalışan podu yok; okunacak bir şey yok.', noPointsYet: 'İlk ölçümler bekleniyor.',
    last24h: '24 saat', perSecond: 'saniyede', limitAbove: 'Sınır', limitBelow: 'Alt sınır', podsRead: '{0} pod',
    findSources: 'Metrik yayınlayanları bul', findingSources: 'Her iş yükünün bir podunda metrikler deneniyor…', sourcesTitle: 'Metrik yayınlayanlar: {0}',
    sourcesHint: 'Her iş yükünün çalışan bir podu, olası portlarından soruldu; veritabanı gibi HTTP konuşmayan sunucuların portları atlandı. Birini açıp metriklerini görün; İzle ile eklediğiniz metriğin grafiği burada çıkar.',
    noSources: 'Sorulan {0} iş yükünden hiçbiri metrik döndürmedi.', sourcesUnfinished: 'Hepsine sormaya süre yetmedi; daha yakından bakmak için bir namespace seçin.',
    openMetrics: 'Metrikleri göster', 'col.address': 'Adres', 'col.metrics': 'Metrik', 'col.workload': 'İş yükü',
    certificates: 'Sertifikalar', uptime: 'URL kontrolleri', fromServer: 'Kartal Gözü sunucusundan denetlenir',
    'col.subject': 'Sertifika adı', 'col.issuer': 'Veren', 'col.expires': 'Bitiş', 'col.used': 'Doluluk', 'col.check': 'Kontrol',
    'col.last24h': 'Son 24 saat', 'col.uptime': 'Erişilebilirlik', 'col.response': 'Yanıt', 'col.certificate': 'Sertifika',
    expiresIn: '{0} sonra', expiredAgo: '{0} önce doldu', inodesUsed: 'inode: %{0} dolu',
    volumeUseHint: 'Bilinmiyor. Agent, KARTAL_VOLUME_STATS açıkken (rbac-volumes.yaml) çalışan bir pod’un bağladığı disklerin doluluğunu kubelet’lerden okur.',
    certificatesHint: 'kubernetes.io/tls Secret’larının tls.crt’sinden; agent’ta KARTAL_TLS_SECRETS açıkken (rbac-certificates.yaml). Anahtarlar hiç okunmaz. {0} gün içinde dolanlar işaretlenir.',
    checksHint: 'Sunucu her adresi kendisi sorar ve son 24 saatin sonuçlarını bellekte tutar. Cevap vermeyen bir adres ya da süresi yaklaşan bir sertifika uyarı oluşturur.',
    noChecks: 'Henüz URL kontrolü yok.', addCheck: 'Kontrol ekle', removeCheck: 'Kaldır', removeCheckTitle: 'Kontrolü kaldır',
    removeCheckConfirm: '{0} kontrolü kaldırılsın mı? Sonuçları da silinir.', checkSaved: 'Kontrol kaydedildi.', checkRemoved: 'Kontrol kaldırıldı.',
    'check.up': 'Çalışıyor', 'check.down': 'Cevap yok', 'check.waiting': 'Bekleniyor', upFor: '{0} süredir', checkName: 'Ad',
    checkURL: 'Adres', checkURLHelp: 'http ya da https; belirtilmezse https kullanılır. Adresi sunucunun kendisi sorar, oradan erişilebilir olmalı.',
    checkInterval: 'Sıklık', checkTimeout: 'Zaman aşımı (saniye)', checkStatus: 'Beklenen durum kodu', checkStatusHelp: 'Boş: 400’ün altındaki her kod.',
    checkContains: 'Cevapta geçmesi gereken metin', checkInsecure: 'Sertifikayı doğrulama (bitiş tarihi yine izlenir)',
    tryCheck: 'Şimdi dene', trying: 'Soruluyor…', tryOK: '✓ {1} ms içinde {0} döndü', certUntil: 'sertifika {0} tarihine kadar geçerli',
    hourFailed: '{0}: {2} istekten {1} tanesi başarısız', hourNone: '{0}: sonuç yok', newCheck: 'Yeni URL kontrolü', editCheck: 'URL kontrolü',
    critical: 'kritik', warning: 'uyarı',
    auditEmpty: 'Kartal Gözü üzerinden henüz bir değişiklik yapılmadı.',
    auditHint: 'Son 1000 değişiklik bellekte tutulur; sunucu logu hepsini saklar.', ok: 'tamam',
  },
};

// ---------------------------------------------------------------- helpers

const enc = encodeURIComponent;
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const isMac = navigator.userAgent.includes('Mac');

// Browser storage can be missing or throw (private mode, blocked site data),
// so every access goes through these two.
function readStore(area, key) {
  try { return window[area].getItem(key); } catch { return null; }
}
function writeStore(area, key, value) {
  try {
    if (value == null) window[area].removeItem(key);
    else window[area].setItem(key, value);
  } catch { /* not kept; everything still works for this visit */ }
}

let lang = readStore('localStorage', 'kartal.lang') ||
  ((navigator.language || '').toLowerCase().startsWith('tr') ? 'tr' : 'en');

function t(key, ...args) {
  const s = (STRINGS[lang] && STRINGS[lang][key]) || STRINGS.en[key] || key;
  return args.length ? s.replace(/\{(\d)\}/g, (_, i) => String(args[i])) : s;
}

// h builds an element. Text always goes in as text nodes, never as HTML.
function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style') Object.assign(el.style, v);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v === true || k === 'value') el[k] = v;
    else el.setAttribute(k, v);
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c != null && c !== false) el.append(c instanceof Node ? c : String(c));
  }
}
function fill(el, ...children) {
  el.replaceChildren();
  append(el, children);
}

function button(label, onclick, cls) {
  return h('button', { type: 'button', class: cls ? 'btn ' + cls : 'btn', onclick }, label);
}
function linkButton(label, href) {
  return h('a', { class: 'btn', href }, label);
}
function pill(text, kind) {
  return h('span', { class: 'status-' + kind }, text);
}
function panel(title, body, cls) {
  return h('section', { class: cls ? 'panel ' + cls : 'panel' }, title == null ? null : h('h2', null, title), body);
}
function emptyState(text) {
  return h('div', { class: 'panel' }, h('div', { class: 'empty-note' }, text));
}
function mono(text) {
  return h('span', { class: 'mono' }, text);
}

// when turns an API timestamp into milliseconds; Go's zero time means "never".
function when(v) {
  if (typeof v === 'number') return v;
  if (!v || v.startsWith('0001-')) return NaN;
  return Date.parse(v);
}
function span(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm';
  const hr = Math.floor(m / 60);
  if (hr < 24) return hr + 'h' + (hr < 10 && m % 60 ? ' ' + (m % 60) + 'm' : '');
  const d = Math.floor(hr / 24);
  return d < 365 ? d + 'd' : Math.floor(d / 365) + 'y';
}
function ago(v) {
  const at = when(v);
  return Number.isFinite(at) ? span(Date.now() - at) : '—';
}
function age(v) {
  const at = when(v);
  return h('span', { title: Number.isFinite(at) ? new Date(at).toLocaleString() : null }, ago(at));
}
function ageOf(v) {
  const at = when(v);
  return Number.isFinite(at) ? Date.now() - at : null;
}
function duration(start, end) {
  const a = when(start);
  if (!Number.isFinite(a)) return '—';
  const b = when(end);
  return span((Number.isFinite(b) ? b : Date.now()) - a);
}
function cpu(milli) {
  if (milli == null) return '—';
  return milli < 1000 ? Math.round(milli) + 'm' : String(+(milli / 1000).toFixed(1));
}
function cores(milli) {
  return String(+(milli / 1000).toFixed(2));
}
// cpuUnit writes CPU with its unit, for charts where a bare number of cores
// could be read as millicores.
function cpuUnit(milli) {
  return milli < 1000 ? Math.round(milli) + 'm' : +(milli / 1000).toFixed(2) + ' ' + t('cores');
}
// upper capitalizes a label the way the language does (i becomes İ in Turkish).
function upper(s) {
  return s ? s.charAt(0).toLocaleUpperCase(lang) + s.slice(1) : s;
}
function bytes(n) {
  if (n == null) return '—';
  const units = ['B', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return +n.toFixed(n < 10 && i ? 1 : 0) + ' ' + units[i];
}
function pct(used, total) {
  return used != null && total ? Math.round((used / total) * 100) : null;
}
function bar(used, total, cls) {
  const p = pct(used, total);
  if (p == null) return null;
  const w = Math.min(100, p);
  return h('div', { class: 'bar' + (cls ? ' ' + cls : '') + (w >= 90 ? ' full' : w >= 75 ? ' hot' : ''), title: p + '%' },
    h('span', { style: { width: w + '%' } }));
}
// quantity parses the CPU and memory strings of a pod spec.
function quantity(q, milli) {
  if (q == null || q === '') return null;
  const m = String(q).match(/^([0-9.]+)([a-zA-Z]*)$/);
  if (!m) return null;
  const units = {
    '': 1, n: 1e-9, u: 1e-6, m: 1e-3, k: 1e3, M: 1e6, G: 1e9, T: 1e12, P: 1e15, E: 1e18,
    Ki: 1024, Mi: 1024 ** 2, Gi: 1024 ** 3, Ti: 1024 ** 4, Pi: 1024 ** 5, Ei: 1024 ** 6,
  };
  if (!(m[2] in units)) return null;
  const v = parseFloat(m[1]) * units[m[2]];
  return milli ? Math.round(v * 1000) : Math.round(v);
}

function podHealthy(p) {
  return p.phase === 'Succeeded' || (p.phase === 'Running' && p.ready === p.total && !p.reason);
}
// podReplaced: the pod stopped for good and its controller already runs
// another in its place, like an evicted pod of a Deployment. It is only
// left over, as the server counts it (protocol.Pod.Replaced).
const REPLACING = new Set(['Deployment', 'ReplicaSet', 'StatefulSet', 'DaemonSet']);
function podReplaced(p) {
  return p.phase === 'Failed' && REPLACING.has((p.owner || '').split('/')[0]);
}
function podStatus(p) {
  if (podReplaced(p)) return h('span', { class: 'status-idle', title: t('replacedHint') }, podState(p) + ' · ' + t('replaced'));
  return pill(podState(p), podHealthy(p) ? 'ok' : 'bad');
}
function podState(p) {
  if (p.reason) return p.reason;
  if (p.phase === 'Running' && p.ready < p.total) return t('notReady');
  return p.phase || '—';
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast(t('copied'));
  } catch {
    // Clipboard access needs HTTPS or localhost; fall back to a selection.
    const area = h('textarea', { class: 'offscreen' });
    area.value = text;
    document.body.append(area);
    area.select();
    try { document.execCommand('copy'); toast(t('copied')); } catch { /* nothing more to try */ }
    area.remove();
  }
}
function download(text, file) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
  const a = h('a', { href: url, download: file });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

// ---------------------------------------------------------------- state

const state = {
  clusters: null, // summaries from the API, null until the first load
  cluster: '',
  view: 'overview',
  ns: '',
  q: '',
  problems: false,
  rest: [], // extra route segments: group/version/resource in the resource browser
  obj: '', // the object open in the detail panel, see objParam
  tab: '',
  namespaces: null,
  nsError: '',
  nsFilter: '',
  nsMenuOpen: false,
  data: null,
  error: null,
  dirty: false, // new data waits to be drawn until a text selection ends
  discovery: null,
  limit: ROW_LIMIT,
  me: null,
  sort: {},
  clusterMetrics: null,
};
// The remembered sort order of each list, if it still makes sense.
try {
  const saved = JSON.parse(readStore('localStorage', 'kartal.sort') || '{}');
  for (const [view, s] of Object.entries(saved && typeof saved === 'object' ? saved : {})) {
    if (s && typeof s.key === 'string' && (s.dir === 1 || s.dir === -1)) state.sort[view] = { key: s.key, dir: s.dir };
  }
} catch { /* default order */ }

// Favorites are kept per cluster, in this browser only: namespaces, and
// objects as "Kind/namespace/name". Everything favorite is listed first.
let favs = { ns: [], obj: [] };

function favKey() { return 'kartal.fav.' + state.cluster; }
function strings(a) { return Array.isArray(a) ? a.filter(x => typeof x === 'string') : []; }
function readFavs() {
  try {
    const v = JSON.parse(readStore('localStorage', favKey()) || '{}');
    return { ns: strings(v.ns), obj: strings(v.obj) };
  } catch {
    return { ns: [], obj: [] };
  }
}
function toggleIn(list, item) {
  const i = list.indexOf(item);
  if (i >= 0) list.splice(i, 1);
  else list.push(item);
}
function toggleFav(kind, item) {
  toggleIn(favs[kind], item);
  writeStore('localStorage', favKey(), JSON.stringify(favs));
  refreshSide(true);
  renderContent();
  if (state.obj) renderDetailHead();
}
function favRank(key, ns) {
  if (key && favs.obj.includes(key)) return 0;
  return ns && favs.ns.includes(ns) ? 1 : 2;
}
function starButton(on, toggle) {
  return h('button', {
    type: 'button', class: on ? 'star on' : 'star', title: on ? t('unpin') : t('pin'), 'aria-pressed': String(on),
    onclick: e => { e.stopPropagation(); toggle(); },
  }, on ? '★' : '☆');
}

// roleAtLeast tells whether the signed-in user's role reaches role anywhere,
// and agentAllows whether this cluster's agent accepts a kind of action.
function roleAtLeast(role) {
  return !!state.me && (RANK[state.me.role] || 0) >= RANK[role];
}
function agentAllows(cap) {
  const c = currentCluster();
  return !!(c && (c.capabilities || []).includes(cap));
}

// A role may be granted only in some clusters and namespaces; these follow
// the server's rules, so the UI offers what the server will allow.
function nameMatches(pattern, name) {
  return pattern === '*' || (pattern.endsWith('*') ? name.startsWith(pattern.slice(0, -1)) : pattern === name);
}
// roleIn is the user's role in a namespace of the current cluster; the
// namespace '' stands for the whole cluster (nodes, cluster-wide objects).
function roleIn(ns) {
  let best = 0;
  for (const g of (state.me && state.me.grants) || []) {
    const r = RANK[g.role] || 0;
    if (r > best && (!g.scopes.length || g.scopes.some(s => nameMatches(s.cluster, state.cluster) &&
      (ns ? nameMatches(s.namespace, ns) : s.namespace === '*')))) best = r;
  }
  return best;
}
function canIn(role, ns) {
  return roleIn(ns || '') >= RANK[role];
}
// canEverywhere is for the server's own settings.
function canEverywhere(role) {
  return !!state.me && (RANK[state.me.everywhere] || 0) >= RANK[role];
}

// actionButton is hidden from users whose role where the action applies is
// too low, and disabled, with the reason, when the agent does not allow it.
// where is a namespace, '' for the whole cluster, or null for the server.
function actionButton(label, onclick, { role = 'operator', cap = 'write', cls, where } = {}) {
  if (!(where === null ? canEverywhere(role) : canIn(role, where))) return null;
  const b = button(label, onclick, cls);
  if (cap && !agentAllows(cap)) {
    b.disabled = true;
    b.title = t('capMissing.' + cap);
  }
  return b;
}

// ---------------------------------------------------------------- routing

// Routes live in the hash (#/c/<cluster>/<view>/<rest>?ns=&q=&p=1&o=&t=), so
// the server never has to know them and any mount path works.
function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}
function parseRoute() {
  const raw = location.hash.replace(/^#\/?/, '');
  const qi = raw.indexOf('?');
  const parts = (qi < 0 ? raw : raw.slice(0, qi)).split('/').map(safeDecode);
  const params = new URLSearchParams(qi < 0 ? '' : raw.slice(qi + 1));
  const r = {
    cluster: '', view: 'overview', rest: [], ns: params.get('ns') || '', q: params.get('q') || '',
    problems: params.get('p') === '1', obj: params.get('o') || '', tab: params.get('t') || '',
  };
  if (parts[0] === 'c') {
    r.cluster = parts[1] || '';
    if (VIEWS.includes(parts[2])) r.view = parts[2];
    r.rest = parts.slice(3).filter(Boolean);
  }
  return r;
}
function routeHash({ cluster = state.cluster, view = state.view, ns = state.ns, q = '', problems = false, rest = [], obj = '', tab = '' } = {}) {
  const params = new URLSearchParams();
  if (ns) params.set('ns', ns);
  if (q) params.set('q', q);
  if (problems) params.set('p', '1');
  if (obj) params.set('o', obj);
  if (obj && tab) params.set('t', tab);
  const qs = params.toString();
  return '#/c/' + [cluster, view, ...rest].map(enc).join('/') + (qs ? '?' + qs : '');
}
function currentHash(extra) {
  return routeHash(Object.assign({ q: state.q, problems: state.problems, rest: state.rest, obj: state.obj, tab: state.tab }, extra));
}
function go(target) {
  const next = routeHash(target);
  if (next === location.hash) onRoute();
  else location.hash = next;
}

// listKey is what the list part of the page depends on; when only the
// detail panel changes, the list is left alone.
let listKey = null;
function keyOf(r) {
  return [r.cluster, r.view, r.ns, r.q, r.problems, r.rest.join('/')].join('\u0000');
}
// replaceRoute writes a change made in place (filter text, problems only)
// to the address without reloading anything.
function replaceRoute() {
  history.replaceState(null, '', currentHash());
  listKey = keyOf(state);
}

function onRoute() {
  const r = parseRoute();
  const key = keyOf(r);
  if (key === listKey && els.shell) {
    state.obj = r.obj;
    state.tab = r.tab;
    renderDetail();
    return;
  }
  listKey = key;
  const clusterChanged = r.cluster !== state.cluster;
  Object.assign(state, r, { data: null, error: null, limit: ROW_LIMIT });
  if (clusterChanged) {
    state.namespaces = null;
    state.nsError = '';
    state.discovery = null;
    state.clusterMetrics = null;
    favs = readFavs();
    if (state.cluster) writeStore('localStorage', 'kartal.cluster', state.cluster);
  }
  if (els.shell) els.shell.classList.remove('side-open');
  document.title = (state.cluster ? t(state.view) + ' · ' + state.cluster + ' · ' : '') + 'Kartal Gözü';
  state.nsMenuOpen = false;
  renderTop();
  renderSide();
  renderHead();
  renderBanner();
  renderContent();
  renderDetail();
  refresh();
}

// ---------------------------------------------------------------- API

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function getToken() {
  return readStore('sessionStorage', TOKEN_KEY) || readStore('localStorage', TOKEN_KEY) || '';
}
function setToken(token, remember) {
  writeStore('sessionStorage', TOKEN_KEY, token && !remember ? token : null);
  writeStore('localStorage', TOKEN_KEY, token && remember ? token : null);
}

// Parsed lists by URL, with their ETag. A list whose content did not change
// comes back as the very same object: nothing is parsed again, and the views
// can tell that there is nothing to redraw.
const memo = new Map();

// api calls the management API. "no-cache" lets the browser keep list
// responses and revalidate them: unchanged lists come back as 304.
async function api(path, { method = 'GET', body, raw, text = false, signal } = {}) {
  const headers = { Accept: text ? 'text/plain' : 'application/json' };
  const token = getToken();
  if (token) headers.Authorization = 'Bearer ' + token;
  let payload;
  if (raw !== undefined) {
    headers['Content-Type'] = 'application/yaml';
    payload = raw;
  } else if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  const res = await fetch(path.startsWith('/') ? path.slice(1) : 'api/v1/' + path, { method, headers, signal, cache: 'no-cache', body: payload });
  if (!res.ok) {
    let message = res.status + ' ' + res.statusText;
    try {
      const j = await res.json();
      if (j && j.error) message = j.error;
    } catch { /* not JSON */ }
    if (res.status === 401) {
      setToken('', false);
      showLogin(!token ? '' : token.startsWith('kgs_') ? t('sessionEnded') : t('badToken'));
    }
    throw new ApiError(res.status, message);
  }
  if (text) return res.text();
  const etag = res.headers.get('ETag');
  if (!etag) return res.json();
  const hit = memo.get(path);
  if (hit && hit.etag === etag) return hit.value;
  const value = await res.json();
  memo.delete(path);
  memo.set(path, { etag, value });
  if (memo.size > 50) memo.delete(memo.keys().next().value);
  return value;
}

function clusterPath(cluster = state.cluster) { return 'clusters/' + enc(cluster); }

let seq = 0;
let inflight = null;
let timer = 0;

function scheduleRefresh() {
  clearTimeout(timer);
  timer = setTimeout(() => {
    if (document.hidden) scheduleRefresh();
    else refresh({ auto: true });
  }, REFRESH_MS);
}
function stopRefresh() {
  clearTimeout(timer);
  seq++;
  if (inflight) inflight.abort();
}

async function refresh({ auto = false } = {}) {
  const my = ++seq;
  if (inflight) inflight.abort();
  const ctl = new AbortController();
  inflight = ctl;
  const signal = ctl.signal;
  try {
    const [clusters, me] = await Promise.all([api('clusters', { signal }), state.me ? state.me : api('me', { signal })]);
    if (my !== seq) return;
    state.clusters = clusters;
    if (!state.me) {
      // What the user may do decides which tabs and buttons appear.
      state.me = me;
      renderTop();
      renderDetail();
    }
    if (!clusters.some(c => c.name === state.cluster)) {
      const saved = readStore('localStorage', 'kartal.cluster');
      const pick = clusters.find(c => c.name === saved) || clusters.find(c => c.status === 'online') || clusters[0];
      if (pick) {
        location.replace(routeHash({ cluster: pick.name, view: state.view, ns: state.cluster ? '' : state.ns }));
        return;
      }
      state.error = new ApiError(-1, t('noClusters'));
      renderTop();
      renderContent();
      return;
    }
    if (topSignature() !== topSig) renderTop();
    renderBanner();
    if (!currentCluster().collectedAt && !ALL_CLUSTERS.has(state.view) && !SERVER_VIEWS.has(state.view)) {
      // Nothing to ask for until the agent's first report arrives.
      state.namespaces = null;
      state.nsError = t('waitingAgent');
      state.data = null;
      state.error = new ApiError(503, '');
      refreshSide(true);
      renderContent();
      return;
    }
    // Live views ask the agent each time; they reload on demand only.
    const keep = auto && LIVE_VIEWS.has(state.view) && state.data;
    const [ns, data] = await Promise.allSettled([
      currentCluster().collectedAt ? api(clusterPath() + '/namespaces', { signal }) : Promise.resolve(null),
      keep ? Promise.resolve(state.data) : loadView(signal),
    ]);
    if (my !== seq) return;
    let sideChanged = true;
    if (ns.status === 'fulfilled') {
      sideChanged = ns.value !== state.namespaces || state.nsError !== '';
      state.namespaces = ns.value;
      state.nsError = '';
    } else {
      state.nsError = ns.reason.message;
    }
    let changed = true;
    if (data.status === 'fulfilled') {
      // Unchanged data is drawn again once a minute, for the ages it shows.
      changed = state.error != null || !sameData(state.data, data.value) || (state.view === 'overview' && sideChanged) ||
        Date.now() - drawnAt > 60000;
      state.data = data.value;
      state.error = null;
    } else {
      state.error = data.reason;
    }
    refreshSide(sideChanged);
    if (changed) {
      // Redrawing would throw away text being selected (a pod name to copy,
      // say); wait until the selection is gone.
      if (auto && selectionInside(els.content)) state.dirty = true;
      else renderContent();
    }
    updateStamp();
    if (auto) detailTick();
  } catch (e) {
    if (my !== seq || e.name === 'AbortError') return;
    state.error = e;
    renderContent();
  } finally {
    if (my === seq) scheduleRefresh();
  }
}

// sameData tells whether a refresh brought nothing new. Unchanged lists are
// the very same objects (see memo); the overview's summary is compared by the
// parts it shows.
function sameData(a, b) {
  if (!a || !b) return false;
  const shown = s => JSON.stringify([s.counts, s.capacity, s.requests, s.usage, s.errors]);
  return Object.keys(b).every(k => {
    if (a[k] === b[k]) return true;
    if (k === 'summary') return shown(a.summary) === shown(b.summary);
    // Alerts, the audit log, changes, versions and checks have no ETag; they
    // are small.
    if (k === 'alerts' || ['audit', 'changes', 'releases', 'uptime', 'appmetrics'].includes(state.view)) return JSON.stringify(a[k]) === JSON.stringify(b[k]);
    return false;
  });
}

function selectionInside(el) {
  const s = window.getSelection();
  return !!(el && s && !s.isCollapsed && s.rangeCount && el.contains(s.getRangeAt(0).commonAncestorContainer));
}

async function loadView(signal) {
  const c = clusterPath();
  const nsq = state.ns ? '?namespace=' + enc(state.ns) : '';
  switch (state.view) {
    case 'overview': {
      // Totals come from the summary (or the namespace's counts); only the
      // items that need attention are downloaded.
      const pq = '?problems=true' + (state.ns ? '&namespace=' + enc(state.ns) : '');
      const [summary, nodes, workloads, pods, events, usage] = await Promise.all([
        api(c, { signal }), api(c + '/nodes', { signal }), api(c + '/workloads' + pq, { signal }),
        api(c + '/pods' + pq, { signal }), api(c + '/events' + nsq, { signal }), clusterUsage(signal)]);
      return { summary, nodes, workloads, pods, events, usage };
    }
    case 'resources':
      return loadResources(signal);
    case 'nodes':
    case 'namespaces':
      return { items: await api(c + '/' + state.view, { signal }) };
    case 'helm':
      return { items: await api(c + '/helm', { signal }) };
    case 'alerts':
      return { alerts: await api('alerts', { signal }) };
    case 'audit':
      // A viewer gets the server's refusal, which says which role it takes.
      return { items: await api('audit', { signal }) };
    case 'changes': {
      const q = new URLSearchParams({ cluster: state.cluster });
      if (state.ns) q.set('namespace', state.ns);
      return { items: await api('changes?' + q, { signal }) };
    }
    case 'uptime':
      return { checks: await api('checks', { signal }) };
    case 'appmetrics': {
      const q = new URLSearchParams({ hours: String(state.watchHours || 1) });
      if (state.ns) q.set('namespace', state.ns);
      return { watches: await api(c + '/watches?' + q, { signal }) };
    }
    case 'releases':
      return { items: await api('releases', { signal }) };
    default: {
      const kind = VIEW_KIND[state.view];
      if (kind) return { items: ofKind(await api(c + '/workloads' + nsq, { signal }), kind) };
      return { items: await api(c + '/' + state.view + nsq, { signal }) };
    }
  }
}

// clusterUsage is the overview's chart data, fetched once a minute: the
// history only gains a point per minute anyway.
async function clusterUsage(signal) {
  const cached = state.clusterMetrics;
  if (cached && cached.cluster === state.cluster && Date.now() - cached.at < METRICS_MS) return cached.value;
  const c = currentCluster();
  let value = null;
  // The cluster's usage belongs to the whole cluster, not a namespace.
  if (c && c.metricsAvailable && roleIn('') > 0) {
    try {
      value = await api(clusterPath() + '/metrics?kind=cluster&hours=1', { signal });
    } catch (e) {
      if (e.name === 'AbortError') throw e;
    }
  }
  state.clusterMetrics = { cluster: state.cluster, at: Date.now(), value };
  return value;
}

// ofKind picks one kind out of the workloads list. Results are kept per list,
// so an unchanged list gives the very same array and nothing is redrawn.
const kindCache = new WeakMap();
function ofKind(list, kind) {
  let byKind = kindCache.get(list);
  if (!byKind) {
    byKind = {};
    kindCache.set(list, byKind);
  }
  if (!byKind[kind]) byKind[kind] = list.filter(w => w.kind === kind);
  return byKind[kind];
}

async function loadResources(signal) {
  const c = clusterPath();
  if (!state.discovery || state.discovery.cluster !== state.cluster) {
    const d = await api(c + '/resources', { signal });
    state.discovery = { cluster: state.cluster, resources: d.resources || [], errors: d.errors || [] };
  }
  const [group, version, resource] = state.rest;
  if (!resource) return { type: null };
  const type = state.discovery.resources.find(r => (r.group || 'core') === group && r.version === version && r.resource === resource) ||
    { group: group === 'core' ? '' : group, version, resource, kind: resource, namespaced: true };
  const nsq = type.namespaced && state.ns ? '?namespace=' + enc(state.ns) : '';
  const items = await api(c + '/resources/' + [group, version, resource].map(enc).join('/') + nsq, { signal });
  return { type, items };
}

// ---------------------------------------------------------------- shell

const root = document.getElementById('app');
const toasts = h('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' });
const els = {};

function startApp() {
  listKey = null;
  els.top = h('header', { class: 'top' });
  els.nsPicker = h('div', { class: 'ns-picker' });
  els.pinned = h('div');
  els.pinnedBox = h('div', { hidden: true }, h('h3', null, h('span', null, '★ ' + t('pinned'))), els.pinned);
  els.nav = h('nav', { class: 'nav', 'aria-label': t('menu') });
  navSig = '';
  els.side = h('aside', { class: 'side' },
    els.nsPicker,
    els.pinnedBox,
    els.nav);
  els.head = h('div');
  els.banner = h('div');
  els.content = h('div');
  els.main = h('main', { class: 'main' }, els.head, els.banner, els.content);
  els.detail = h('aside', { class: 'detail-panel', hidden: true, 'aria-label': t('details') });
  els.detailResize = h('div', { class: 'detail-resize', title: t('resize'), onmousedown: startResize });
  const width = Number(readStore('localStorage', 'kartal.detailWidth'));
  if (width >= 420) els.detail.style.width = width + 'px';
  els.shell = h('div', { class: 'shell' }, els.top, els.side, els.main, els.detail);
  resetDetail();
  fill(root, els.shell, toasts);
  onRoute();
}

function currentCluster() {
  return (state.clusters || []).find(c => c.name === state.cluster);
}

// The top bar is redrawn only when something it shows changed.
let topSig = '';
function topSignature() {
  return JSON.stringify([state.cluster, state.view, lang, theme(), !!getToken(), state.me,
    (state.clusters || []).map(c => [c.name, c.status, c.counts, c.alerts])]);
}

function renderTop() {
  if (!els.top) return;
  topSig = topSignature();
  fill(els.top,
    h('button', { type: 'button', class: 'icon-btn menu-btn', title: t('menu'), onclick: () => els.shell.classList.toggle('side-open') }, '☰'),
    h('a', { class: 'brand', href: '#/' }, h('img', { src: '_ui/eagle.svg', alt: '' }), h('span', { class: 'brand-name' }, 'Kartal Gözü')),
    h('div', { class: 'clusters' }, (state.clusters || []).map(clusterChip)),
    h('button', { type: 'button', class: 'btn search-btn', title: t('searchTitle'), onclick: openPalette },
      '⌕', h('span', { class: 'label' }, t('search')), h('kbd', null, isMac ? '⌘K' : 'Ctrl K')),
    state.me ? h('span', { class: 'user-chip', title: t('role.' + state.me.role) }, state.me.name,
      h('span', { class: 'muted' }, ' · ' + t('role.' + state.me.role))) : null,
    h('button', { type: 'button', class: 'icon-btn', title: t('language'), onclick: toggleLang }, lang === 'tr' ? 'EN' : 'TR'),
    h('button', { type: 'button', class: 'icon-btn', title: t('theme'), onclick: toggleTheme }, theme() === 'dark' ? '☀' : '☾'),
    getToken() ? h('button', { type: 'button', class: 'icon-btn', title: t('logout'), onclick: logout }, '↪') : null);
}

function clusterChip(c) {
  const n = c.counts || {};
  const problems = (n.podsUnhealthy || 0) + (n.nodesNotReady || 0) + (n.workloadsDegraded || 0);
  const dot = c.status === 'online' ? (problems ? 'warn' : 'ok') : c.status === 'offline' ? 'bad' : '';
  const title = t('status.' + c.status) + (c.lastSeen ? ' · ' + t('lastSeen', ago(c.lastSeen)) : '');
  return h('a', {
    class: c.name === state.cluster ? 'chip active' : 'chip', title,
    href: routeHash({ cluster: c.name, view: state.view, ns: '' }),
  }, h('span', { class: 'dot ' + dot }), c.name, problems && c.status === 'online' ? h('span', { class: 'badge warn' }, problems) : null);
}

// ---------------------------------------------------------------- sidebar

// renderSide draws the whole sidebar. refreshSide redraws only what new data
// can change, and leaves the namespace search the user may be typing in alone.
function renderSide() {
  if (!els.side) return;
  renderNsPicker();
  renderPinned();
  renderNav();
}
function refreshSide(dataChanged) {
  if (!els.side) return;
  if (dataChanged) {
    if (state.nsMenuOpen) renderNsMenuList();
    renderPinned();
  }
  renderNav();
}

function nsSummary(name) {
  return (state.namespaces || []).find(n => n.name === name) || { name };
}

function selectNamespace(ns) {
  state.nsMenuOpen = false;
  const view = CLUSTER_SCOPED.has(state.view) ? 'overview' : state.view;
  go({ view, ns, rest: view === 'resources' ? state.rest : [] });
}

function closeNsMenu() {
  state.nsMenuOpen = false;
  renderNsPicker();
}

// The namespace picker sets the scope of every view. Its list keeps each
// namespace's Pods and Events shortcuts, pinned namespaces first.
function renderNsPicker() {
  if (!els.nsPicker) return;
  const open = state.nsMenuOpen;
  const btn = h('button', {
    type: 'button', class: open ? 'ns-button open' : 'ns-button', title: t('chooseNamespace'), 'aria-expanded': String(open),
    onclick: () => { state.nsMenuOpen = !state.nsMenuOpen; renderNsPicker(); },
  }, h('span', { class: 'ns-label' }, t('namespace')), h('span', { class: 'ns-value' }, state.ns || t('allNamespaces')), h('span', { class: 'caret' }, '▾'));
  if (!open) {
    els.nsMenuList = null;
    fill(els.nsPicker, btn);
    return;
  }
  const search = h('input', {
    type: 'text', class: 'filter', value: state.nsFilter, placeholder: t('filterNamespaces'), 'aria-label': t('filterNamespaces'),
    oninput: e => { state.nsFilter = e.target.value; renderNsMenuList(); },
    onkeydown: e => {
      if (e.key !== 'Enter') return;
      const first = els.nsMenuList.querySelector('.name');
      if (first) first.click();
    },
  });
  els.nsMenuList = h('div', { class: 'ns-menu-list' });
  fill(els.nsPicker, btn, h('div', { class: 'ns-menu' }, search, els.nsMenuList));
  renderNsMenuList();
  search.focus();
}

function renderNsMenuList() {
  if (!els.nsMenuList) return;
  const list = state.namespaces;
  if (!list) {
    fill(els.nsMenuList, h('div', { class: 'empty-note' }, state.nsError || t('loading')));
    return;
  }
  const q = state.nsFilter.trim().toLowerCase();
  const shown = list.filter(n => !q || n.name.toLowerCase().includes(q));
  const pinned = shown.filter(n => favs.ns.includes(n.name));
  const rest = shown.filter(n => !favs.ns.includes(n.name));
  fill(els.nsMenuList,
    q ? null : h('div', { class: state.ns ? 'row' : 'row active' },
      h('span', { class: 'star-space' }),
      h('button', { type: 'button', class: 'name', onclick: () => selectNamespace('') }, t('allNamespaces'))),
    pinned.map(n => namespaceRow(n, true)),
    pinned.length && rest.length ? h('div', { class: 'ns-sep' }) : null,
    rest.map(n => namespaceRow(n, false)),
    shown.length ? null : h('div', { class: 'empty-note' }, t('noMatch')));
}

function renderPinned() {
  if (!els.pinned) return;
  const rows = [...favs.ns.map(ns => namespaceRow(nsSummary(ns), true)), ...favs.obj.map(objectRow)];
  // Nothing pinned yet: the section stays out of the way.
  els.pinnedBox.hidden = !rows.length;
  fill(els.pinned, rows);
}

// navCounts are the numbers in the navigation: the selected namespace's, or
// the whole cluster's. Nodes, namespaces and alerts are always the cluster's.
function navCounts() {
  const c = currentCluster();
  const cluster = Object.assign({}, (c && c.counts) || {}, { alerts: c ? c.alerts || 0 : 0 });
  if (!state.ns) return cluster;
  return Object.assign({}, (state.namespaces || []).find(n => n.name === state.ns),
    { nodes: cluster.nodes, nodesNotReady: cluster.nodesNotReady, namespaces: cluster.namespaces, alerts: cluster.alerts });
}

// The navigation's groups open and close with a click. The group holding
// the current view opens by itself; the others stay as the user left them,
// remembered in this browser.
const NAV_OPEN_KEY = 'kartal.navOpen';
const navOpen = new Set((readStore('localStorage', NAV_OPEN_KEY) || '').split(',').filter(Boolean));
let navShutAt = null; // the view whose own group the user closed

function groupOpen(section) {
  if (section.items.includes(state.view)) return navShutAt !== state.view;
  return navOpen.has(section.group);
}

function toggleGroup(section) {
  if (groupOpen(section)) {
    navOpen.delete(section.group);
    if (section.items.includes(state.view)) navShutAt = state.view;
  } else {
    navOpen.add(section.group);
    if (section.items.includes(state.view)) navShutAt = null;
  }
  writeStore('localStorage', NAV_OPEN_KEY, [...navOpen].join(',') || null);
  navSig = '';
  renderNav();
}

// The navigation is redrawn only when something it shows changed.
let navSig = '';
function renderNav() {
  if (!els.nav) return;
  const counts = navCounts();
  const sig = JSON.stringify([state.cluster, state.view, state.ns, lang, counts, state.me]);
  if (sig === navSig) return;
  navSig = sig;
  fill(els.nav, NAV.map(section => {
    // The audit log is for operators; nodes are the whole cluster's.
    const items = section.items.filter(id => (id !== 'audit' || roleAtLeast('operator')) && (id !== 'nodes' || roleIn('') > 0));
    if (!section.group) return items.map(id => navItem(id, counts));
    if (!items.length) return null;
    const open = groupOpen(section);
    // A closed group still shows that something inside needs attention.
    const bad = open ? 0 : items.reduce((n, id) => n + (id === 'events' ? 0 : navProblems(id, counts)), 0);
    const warn = open || bad || !items.includes('events') ? 0 : navProblems('events', counts);
    return [
      h('button', { type: 'button', class: 'nav-group', 'aria-expanded': String(open), onclick: () => toggleGroup(section) },
        h('span', { class: 'caret', 'aria-hidden': 'true' }, '›'),
        h('span', { class: 'nav-label' }, t(section.group)),
        bad ? h('span', { class: 'badge bad' }, bad) : warn ? h('span', { class: 'badge warn' }, warn) : null),
      open ? h('div', { class: 'nav-sub' }, items.map(id => navItem(id, counts))) : null,
    ];
  }));
}

function navProblems(id, counts) {
  const problemKey = (NAV_COUNT[id] || [])[1];
  return [].concat(problemKey || []).reduce((n, k) => n + (counts[k] || 0), 0);
}

function navItem(id, counts) {
  const totalKey = (NAV_COUNT[id] || [])[0];
  const total = totalKey ? counts[totalKey] : null;
  const problems = navProblems(id, counts);
  const active = id === state.view;
  return h('a', { class: active ? 'nav-item active' : 'nav-item', href: routeHash({ view: id }), 'aria-current': active ? 'page' : null },
    h('span', { class: 'nav-label' }, t(id)),
    problems ? h('span', { class: id === 'events' ? 'badge warn' : 'badge bad' }, problems) : null,
    total != null ? h('span', { class: 'nav-count' }, total) : null);
}

// namespaceRow is one namespace with its Pods and Events shortcuts.
function namespaceRow(n, pinned) {
  return h('div', { class: state.ns === n.name ? 'row active' : 'row' },
    starButton(pinned, () => toggleFav('ns', n.name)),
    h('button', { type: 'button', class: 'name', title: t('scopeTo', n.name), onclick: () => selectNamespace(n.name) }, n.name),
    n.podsUnhealthy ? h('span', { class: 'badge bad', title: t('unhealthyPods', n.podsUnhealthy) }, n.podsUnhealthy) : null,
    h('span', { class: 'shortcuts' },
      h('a', { class: 'shortcut', href: routeHash({ view: 'pods', ns: n.name }), title: t('podsIn', n.name) }, t('pods')),
      h('a', { class: n.warnings ? 'shortcut warn' : 'shortcut', href: routeHash({ view: 'events', ns: n.name }), title: t('eventsIn', n.name) },
        t('events'), n.warnings ? ' ' + n.warnings : '')));
}

function splitKey(key) {
  const [kind, ns, ...name] = key.split('/');
  return { kind, ns, name: name.join('/') };
}

function objectRow(key) {
  const { kind, ns, name } = splitKey(key);
  const gvr = KIND_API[kind];
  return h('div', { class: 'row' },
    starButton(true, () => toggleFav('obj', key)),
    gvr
      ? h('button', { type: 'button', class: 'name', title: kind + ' ' + (ns ? ns + '/' : '') + name, onclick: () => openDetail({ gvr, ns, name }) },
        name, h('span', { class: 'muted' }, ' · ' + kind + (ns ? ' · ' + ns : '')))
      : h('span', { class: 'name' }, name),
    WORKLOAD_KINDS.has(kind) || kind === 'Pod' ? h('span', { class: 'shortcuts' },
      kind === 'Pod'
        ? h('button', { type: 'button', class: 'shortcut', title: t('logsOf', name), onclick: () => openDetail({ gvr, ns, name }, 'logs') }, t('logs'))
        : h('a', { class: 'shortcut', href: routeHash({ view: 'pods', ns, q: name }), title: t('podsIn', name) }, t('pods'))) : null);
}

// ---------------------------------------------------------------- main area

function renderHead() {
  if (!els.head) return;
  const v = state.view;
  const table = TABLES[v];
  els.filter = v === 'overview' ? null : h('input', {
    type: 'text', class: 'filter', value: state.q, placeholder: t('filterRows'), 'aria-label': t('filterRows'),
    oninput: e => {
      state.q = e.target.value;
      state.limit = ROW_LIMIT;
      replaceRoute();
      renderContent();
    },
  });
  els.updated = h('span', { class: 'muted' });
  const scope = CLUSTER_SCOPED.has(v)
    ? h('span', { class: 'muted' }, t(SERVER_VIEWS.has(v) ? 'fromServer' : ALL_CLUSTERS.has(v) ? 'allClusters' : 'clusterWide'))
    : state.ns
      ? h('span', { class: 'chip active' }, t('namespace') + ': ' + state.ns,
        h('button', { type: 'button', class: 'star', title: t('allNamespaces'), onclick: () => selectNamespace('') }, '✕'))
      : h('span', { class: 'muted' }, t('allNamespaces'));
  fill(els.head,
    h('div', { class: 'toolbar' },
      h('h1', null, t(v)), scope,
      (table && table.problem) || v === 'releases' ? h('button', {
        type: 'button', class: state.problems ? 'chip active' : 'chip',
        onclick: () => {
          state.problems = !state.problems;
          replaceRoute();
          renderHead();
          renderContent();
        },
      }, v === 'releases' ? '≠ ' + t('onlyDifferences') : '⚠ ' + t('problemsOnly')) : null,
      els.filter, els.updated,
      h('button', { type: 'button', class: 'icon-btn', title: t('refresh'), onclick: () => refresh() }, '↻')));
  updateStamp();
}

function updateStamp() {
  if (!els.updated) return;
  const c = currentCluster();
  const at = c ? when(c.collectedAt) : NaN;
  els.updated.textContent = Number.isFinite(at) ? t('dataFrom', new Date(at).toLocaleTimeString()) : '';
  els.updated.title = c ? [c.kubeVersion && 'Kubernetes ' + c.kubeVersion, c.agentVersion && 'agent ' + c.agentVersion].filter(Boolean).join(' · ') : '';
}

function renderBanner() {
  if (!els.banner) return;
  const c = currentCluster();
  fill(els.banner, c && c.status === 'offline' ? h('div', { class: 'banner' }, '⚠ ', t('offlineBanner', ago(c.lastSeen))) : null);
}

let drawnAt = 0;

function renderContent() {
  if (!els.content) return;
  state.dirty = false;
  drawnAt = Date.now();
  if (!state.data) {
    fill(els.content, state.error ? errorPanel(state.error) : h('div', { class: 'empty-note' }, t('loading')));
    return;
  }
  let body;
  switch (state.view) {
    case 'overview': body = renderOverview(state.data); break;
    case 'resources': body = renderResources(state.data); break;
    case 'alerts': body = renderAlerts(state.data.alerts); break;
    case 'audit': body = renderAudit(state.data.items); break;
    case 'changes': body = renderChanges(state.data.items); break;
    case 'releases': body = renderReleases(state.data.items); break;
    case 'uptime': body = renderUptime(state.data.checks); break;
    case 'appmetrics': body = renderAppMetrics(state.data.watches); break;
    case 'certificates':
      body = [renderTable(state.view, state.data.items || []), h('div', { class: 'more-note' }, t('certificatesHint', levels().certificateWarningDays))];
      break;
    default: body = renderTable(state.view, state.data.items || []);
  }
  fill(els.content, state.error ? errorPanel(state.error) : null, body);
}

function errorPanel(e) {
  if (e.status === -1) return emptyState(e.message);
  if (e.status === 503) {
    return panel(t('waitingAgent'), h('div', { class: 'issue' },
      h('div', { class: 'what' }, h('div', null, t('waitingHelp')), e.message ? h('div', { class: 'detail mono' }, e.message) : null)));
  }
  return panel('⚠ ' + t('failed'), h('div', { class: 'issue' }, h('div', { class: 'what mono' }, e.message)), 'errors');
}

// ---------------------------------------------------------------- tables

function nsLink(ns) {
  if (!ns) return '—';
  return h('a', { class: 'ns-link', href: routeHash({ ns, q: state.q, problems: state.problems, rest: state.rest }), title: t('scopeTo', ns) }, ns);
}
// nameLink opens an object's details.
function nameLink(kind, ns, name, extra) {
  const gvr = KIND_API[kind];
  if (!gvr) return h('strong', null, name);
  return h('button', { type: 'button', class: 'link-button', title: extra || null, onclick: () => openDetail({ gvr, ns, name }) }, h('strong', null, name));
}
// objectLink turns an event's "Kind/name" into a link to that object.
function objectLink(ns, object) {
  object = object || '';
  const i = object.indexOf('/');
  const kind = object.slice(0, i);
  const name = object.slice(i + 1);
  const gvr = KIND_API[kind];
  if (i < 0 || !gvr || !name) return object || '—';
  return h('button', { type: 'button', class: 'link-button', onclick: () => openDetail({ gvr, ns: kind === 'Node' ? '' : ns, name }) }, object);
}
function hostLink(host, path, tls) {
  const label = (host || '*') + (path || '');
  if (!host || host.includes('*')) return h('span', { class: 'mono' }, label);
  let url;
  try {
    url = new URL((tls ? 'https://' : 'http://') + host + (path && path.startsWith('/') ? path : '/'));
  } catch {
    return h('span', { class: 'mono' }, label);
  }
  return h('a', { class: 'mono ns-link', href: url.href, target: '_blank', rel: 'noopener noreferrer' }, label);
}
function portText(p) {
  let s = p.port + (p.nodePort ? ':' + p.nodePort : '') + '/' + p.protocol;
  if (p.targetPort && p.targetPort !== String(p.port)) s += '→' + p.targetPort;
  return s;
}
const ACCESS = { ReadWriteOnce: 'RWO', ReadOnlyMany: 'ROX', ReadWriteMany: 'RWX', ReadWriteOncePod: 'RWOP' };

function nodeStatus(n) {
  const parts = [n.ready ? 'Ready' : 'NotReady'];
  if (n.unschedulable) parts.push('SchedulingDisabled');
  parts.push(...(n.pressure || []));
  return pill(parts.join(', '), !n.ready ? 'bad' : parts.length > 1 ? 'warn' : 'ok');
}
// capacityCell shows usage and requests against what a node can hand out.
function capacityCell(usage, requests, allocatable, fmt) {
  return h('div', { class: 'bar-cell' },
    h('div', { class: 'bar-line' }, h('span', { class: 'muted' }, t('used')), ' ', usage != null ? fmt(usage) : '—', ' / ', fmt(allocatable)),
    bar(usage, allocatable),
    h('div', { class: 'bar-line' }, h('span', { class: 'muted' }, t('requested')), ' ', fmt(requests || 0), requests ? ' (' + pct(requests, allocatable) + '%)' : ''),
    bar(requests || 0, allocatable, 'requested'));
}
// jobStatus reads the Job's own condition; failed pods alone only mean it is
// retrying. Without a condition (an older agent), the counts decide.
function jobStatus(j) {
  if (j.condition === 'Failed') return pill('Failed', 'bad');
  if (j.condition === 'Complete' || (j.succeeded >= (j.completions || 1) && !j.active)) return pill('Complete', 'ok');
  if (j.failed > 0) return pill('Retrying', 'warn');
  if (j.active > 0) return pill('Running', 'ok');
  return pill('Pending', 'warn');
}
function countCell(total, bad) {
  return bad ? [String(total || 0), ' ', h('span', { class: 'badge bad' }, bad)] : String(total || 0);
}
function detailButton(kind, ns, name) {
  const gvr = KIND_API[kind];
  return gvr ? button(t('details'), () => openDetail({ gvr, ns, name })) : null;
}

// levels are where the server's alerts begin, for volumes and certificates.
function levels() {
  return Object.assign({ volumeWarning: 85, volumeCritical: 95, certificateWarningDays: 14, certificateCriticalDays: 3 },
    state.me && state.me.levels);
}

// fillOf is how full a volume is, in percent, by space or by inodes,
// whichever is fuller; null when the agent does not say.
function fillOf(v) {
  const parts = [];
  if (v.capacityBytes) parts.push((100 * v.usedBytes) / v.capacityBytes);
  if (v.inodes) parts.push((100 * v.inodesUsed) / v.inodes);
  return parts.length ? Math.max(...parts) : null;
}

function volumeUse(v) {
  const p = fillOf(v);
  if (p == null) return h('span', { class: 'muted', title: t('volumeUseHint') }, '—');
  const lv = levels();
  const inodes = v.inodes ? Math.round((100 * v.inodesUsed) / v.inodes) : null;
  const level = p >= lv.volumeCritical ? 'bad' : p >= lv.volumeWarning ? 'warn' : '';
  return h('div', { class: 'bar-cell', title: inodes != null ? t('inodesUsed', inodes) : null },
    h('span', { class: level ? 'status-' + level : null }, Math.round(p) + '%'),
    v.capacityBytes ? h('span', { class: 'muted' }, ' · ' + bytes(v.usedBytes) + ' / ' + bytes(v.capacityBytes)) : null,
    h('div', { class: 'bar' + (level === 'bad' ? ' full' : level ? ' hot' : '') }, h('span', { style: { width: Math.min(100, p) + '%' } })));
}

// certLevel is ok, warn or bad, by how soon a certificate expires.
function certLevel(c) {
  const at = when(c.notAfter);
  if (c.error || !Number.isFinite(at)) return 'bad';
  const days = (at - Date.now()) / 86400000;
  const lv = levels();
  return days <= lv.certificateCriticalDays ? 'bad' : days <= lv.certificateWarningDays ? 'warn' : 'ok';
}

function expiresCell(notAfter) {
  const at = when(notAfter);
  if (!Number.isFinite(at)) return '—';
  const left = at - Date.now();
  return h('span', { class: 'status-' + certLevel({ notAfter }), title: new Date(at).toLocaleString() },
    left > 0 ? t('expiresIn', span(left)) : t('expiredAgo', span(-left)));
}

function refTable(kind) {
  return {
    key: x => kind + '/' + x.namespace + '/' + x.name,
    text: x => [x.namespace, x.name],
    columns: [
      ['name', x => nameLink(kind, x.namespace, x.name), x => x.name],
      ['namespace', x => nsLink(x.namespace), x => x.namespace],
      ['age', x => age(x.createdAt), x => ageOf(x.createdAt)],
    ],
    actions: x => [detailButton(kind, x.namespace, x.name)],
  };
}

function workloadActions(w) {
  return [
    linkButton(t('pods'), routeHash({ view: 'pods', ns: w.namespace, q: w.name })),
    detailButton(w.kind, w.namespace, w.name),
    w.kind === 'DaemonSet' ? null : actionButton(t('scale'), () => scaleWorkload(w), { where: w.namespace }),
    actionButton(t('restart'), () => restartWorkload(w), { cls: 'danger', where: w.namespace }),
  ];
}

// TABLES describes every list view: columns as [header, cell, sort value],
// the text the filter searches, the favorite key, what counts as a problem
// and the row actions.
const TABLES = {
  workloads: {
    key: w => w.kind + '/' + w.namespace + '/' + w.name,
    problem: w => w.ready < w.desired,
    text: w => [w.kind, w.namespace, w.name, ...(w.images || [])],
    columns: [
      ['name', w => nameLink(w.kind, w.namespace, w.name), w => w.name],
      ['kind', w => w.kind, w => w.kind],
      ['namespace', w => nsLink(w.namespace), w => w.namespace],
      ['ready', w => pill(w.ready + '/' + w.desired, w.ready < w.desired ? 'bad' : 'ok'), w => (w.desired ? w.ready / w.desired : 1)],
      ['updated', w => w.updated, w => w.updated],
      ['cpu', w => (w.usage ? cpu(w.usage.cpuMilli) : '—'), w => (w.usage ? w.usage.cpuMilli : null)],
      ['memory', w => (w.usage ? bytes(w.usage.memoryBytes) : '—'), w => (w.usage ? w.usage.memoryBytes : null)],
      ['images', w => h('span', { class: 'mono' }, (w.images || []).join(', '))],
      ['age', w => age(w.createdAt), w => ageOf(w.createdAt)],
    ],
    actions: workloadActions,
  },
  pods: {
    key: p => 'Pod/' + p.namespace + '/' + p.name,
    problem: p => !podHealthy(p) && !podReplaced(p),
    text: p => [p.namespace, p.name, p.phase, p.reason, p.node, p.ip, p.owner],
    columns: [
      ['name', p => nameLink('Pod', p.namespace, p.name, p.owner), p => p.name],
      ['namespace', p => nsLink(p.namespace), p => p.namespace],
      ['status', podStatus, p => podState(p)],
      ['ready', p => p.ready + '/' + p.total, p => (p.total ? p.ready / p.total : 1)],
      ['restarts', p => (p.restarts ? pill(p.restarts, 'warn') : '0'), p => p.restarts],
      ['cpu', p => usageWithRequest(p.usage && p.usage.cpuMilli, p.requests && p.requests.cpuMilli, p.limits && p.limits.cpuMilli, cpu),
        p => (p.usage ? p.usage.cpuMilli : null)],
      ['memory', p => usageWithRequest(p.usage && p.usage.memoryBytes, p.requests && p.requests.memoryBytes, p.limits && p.limits.memoryBytes, bytes),
        p => (p.usage ? p.usage.memoryBytes : null)],
      ['node', p => nodeLink(p.node), p => p.node],
      ['age', p => age(p.startedAt), p => ageOf(p.startedAt)],
    ],
    actions: p => [
      button(t('logs'), () => openDetail({ gvr: KIND_API.Pod, ns: p.namespace, name: p.name }, 'logs')),
      detailButton('Pod', p.namespace, p.name),
      actionButton(t('deletePod'), () => deletePod(p), { cls: 'danger', where: p.namespace }),
    ],
  },
  services: {
    key: s => 'Service/' + s.namespace + '/' + s.name,
    text: s => [s.namespace, s.name, s.type, s.clusterIP],
    columns: [
      ['name', s => nameLink('Service', s.namespace, s.name), s => s.name],
      ['namespace', s => nsLink(s.namespace), s => s.namespace],
      ['type', s => s.type, s => s.type],
      ['clusterIP', s => mono(s.clusterIP || '—')],
      ['ports', s => mono((s.ports || []).map(portText).join(', '))],
      ['age', s => age(s.createdAt), s => ageOf(s.createdAt)],
    ],
    actions: s => [detailButton('Service', s.namespace, s.name)],
  },
  ingresses: {
    key: i => 'Ingress/' + i.namespace + '/' + i.name,
    text: i => [i.namespace, i.name, i.class, ...(i.rules || []).map(r => r.host + r.path + ' ' + r.backend)],
    columns: [
      ['name', i => nameLink('Ingress', i.namespace, i.name), i => i.name],
      ['namespace', i => nsLink(i.namespace), i => i.namespace],
      ['class', i => i.class || '—', i => i.class],
      ['rules', i => (i.rules || []).map(r => h('div', null, hostLink(r.host, r.path, i.tls), h('span', { class: 'muted' }, ' → ' + r.backend)))],
      ['tls', i => (i.tls ? '✓' : '—')],
      ['age', i => age(i.createdAt), i => ageOf(i.createdAt)],
    ],
    actions: i => [detailButton('Ingress', i.namespace, i.name)],
  },
  configmaps: refTable('ConfigMap'),
  secrets: refTable('Secret'),
  certificates: {
    key: c => 'Secret/' + c.namespace + '/' + c.secret,
    problem: c => certLevel(c) !== 'ok',
    text: c => [c.namespace, c.secret, c.subject, c.issuer, c.error].concat(c.dnsNames || []),
    columns: [
      ['name', c => nameLink('Secret', c.namespace, c.secret), c => c.secret],
      ['namespace', c => nsLink(c.namespace), c => c.namespace],
      ['subject', c => (c.error ? h('span', { class: 'status-bad' }, c.error)
        : h('span', { title: (c.dnsNames || []).join('\n') || null }, c.subject || '—',
          (c.dnsNames || []).length > 1 ? h('span', { class: 'muted' }, ' +' + (c.dnsNames.length - 1)) : null)), c => c.subject],
      ['issuer', c => c.issuer || '—', c => c.issuer],
      ['expires', c => (c.error ? '—' : expiresCell(c.notAfter)), c => when(c.notAfter)],
    ],
    actions: c => [detailButton('Secret', c.namespace, c.secret)],
  },
  volumeclaims: {
    key: v => 'PersistentVolumeClaim/' + v.namespace + '/' + v.name,
    problem: v => v.phase !== 'Bound' || fillOf(v) >= levels().volumeWarning,
    text: v => [v.namespace, v.name, v.phase, v.storageClass, v.volumeName],
    columns: [
      ['name', v => nameLink('PersistentVolumeClaim', v.namespace, v.name), v => v.name],
      ['namespace', v => nsLink(v.namespace), v => v.namespace],
      ['status', v => pill(v.phase || '—', v.phase === 'Bound' ? 'ok' : v.phase === 'Lost' ? 'bad' : 'warn'), v => v.phase],
      ['used', volumeUse, v => fillOf(v)],
      ['capacity', v => v.capacity || '—', v => quantity(v.capacity)],
      ['storageClass', v => v.storageClass || '—', v => v.storageClass],
      ['access', v => (v.accessModes || []).map(m => ACCESS[m] || m).join(', ')],
      ['volume', v => mono(v.volumeName || '—')],
      ['age', v => age(v.createdAt), v => ageOf(v.createdAt)],
    ],
    actions: v => [detailButton('PersistentVolumeClaim', v.namespace, v.name)],
  },
  jobs: {
    key: j => 'Job/' + j.namespace + '/' + j.name,
    problem: j => j.condition === 'Failed',
    text: j => [j.namespace, j.name, j.owner],
    columns: [
      ['name', j => nameLink('Job', j.namespace, j.name, j.owner), j => j.name],
      ['namespace', j => nsLink(j.namespace), j => j.namespace],
      ['status', j => jobStatus(j)],
      ['completions', j => j.succeeded + '/' + (j.completions || 1), j => j.succeeded],
      ['failed', j => j.failed || 0, j => j.failed],
      ['started', j => age(j.startedAt), j => ageOf(j.startedAt)],
      ['duration', j => duration(j.startedAt, j.completedAt)],
    ],
    actions: j => [
      linkButton(t('pods'), routeHash({ view: 'pods', ns: j.namespace, q: j.name })),
      detailButton('Job', j.namespace, j.name),
    ],
  },
  cronjobs: {
    key: c => 'CronJob/' + c.namespace + '/' + c.name,
    text: c => [c.namespace, c.name, c.schedule],
    columns: [
      ['name', c => nameLink('CronJob', c.namespace, c.name), c => c.name],
      ['namespace', c => nsLink(c.namespace), c => c.namespace],
      ['schedule', c => mono(c.schedule)],
      ['suspended', c => (c.suspended ? pill(t('yes'), 'warn') : t('no')), c => c.suspended],
      ['active', c => c.active, c => c.active],
      ['lastSchedule', c => age(c.lastSchedule), c => ageOf(c.lastSchedule)],
      ['lastSuccess', c => age(c.lastSuccess), c => ageOf(c.lastSuccess)],
    ],
    actions: c => [
      actionButton(t('runNow'), () => triggerCronJob(c), { where: c.namespace }),
      actionButton(c.suspended ? t('resume') : t('suspend'), () => suspendCronJob(c, !c.suspended), { where: c.namespace }),
      linkButton(t('jobs'), routeHash({ view: 'jobs', ns: c.namespace, q: c.name })),
      detailButton('CronJob', c.namespace, c.name),
    ],
  },
  events: {
    order: (a, b) => when(b.lastSeen) - when(a.lastSeen),
    text: e => [e.namespace, e.object, e.reason, e.message],
    columns: [
      ['lastSeen', e => age(e.lastSeen), e => ageOf(e.lastSeen)],
      ['namespace', e => nsLink(e.namespace), e => e.namespace],
      ['object', e => objectLink(e.namespace, e.object), e => e.object],
      ['reason', e => pill(e.reason, 'warn'), e => e.reason],
      ['message', e => e.message],
      ['count', e => e.count, e => e.count],
    ],
  },
  nodes: {
    key: n => 'Node//' + n.name,
    problem: n => !n.ready || (n.pressure || []).length > 0,
    order: (a, b) => cmp(a.name, b.name),
    text: n => [n.name, n.internalIP, n.kubeletVersion, ...(n.roles || [])],
    columns: [
      ['name', n => nameLink('Node', '', n.name), n => n.name],
      ['status', nodeStatus, n => (n.ready ? 1 : 0)],
      ['roles', n => h('span', { class: 'nowrap' }, (n.roles || []).join(', ') || '—')],
      ['cpu', n => capacityCell(n.usage && n.usage.cpuMilli, n.requests && n.requests.cpuMilli, n.allocatable.cpuMilli, cpu),
        n => pct(n.requests ? n.requests.cpuMilli : 0, n.allocatable.cpuMilli)],
      ['memory', n => capacityCell(n.usage && n.usage.memoryBytes, n.requests && n.requests.memoryBytes, n.allocatable.memoryBytes, bytes),
        n => pct(n.requests ? n.requests.memoryBytes : 0, n.allocatable.memoryBytes)],
      ['pods', n => h('span', { class: 'nowrap' }, n.podCount + ' / ' + (n.allocatable.pods || '—')), n => n.podCount],
      ['version', n => n.kubeletVersion || '—'],
      ['ip', n => mono(n.internalIP || '—')],
      ['age', n => age(n.createdAt), n => ageOf(n.createdAt)],
    ],
    actions: n => [
      linkButton(t('pods'), routeHash({ view: 'pods', ns: '', q: n.name })),
      actionButton(n.unschedulable ? t('uncordon') : t('cordon'), () => cordonNode(n, !n.unschedulable), { where: '' }),
      detailButton('Node', '', n.name),
    ],
  },
  namespaces: {
    fav: n => ['ns', n.name],
    problem: n => n.podsUnhealthy > 0 || n.workloadsDegraded > 0,
    order: (a, b) => cmp(a.name, b.name),
    text: n => [n.name, n.status],
    columns: [
      ['name', n => h('button', { type: 'button', class: 'link-button', title: t('scopeTo', n.name), onclick: () => selectNamespace(n.name) },
        h('strong', null, n.name)), n => n.name],
      ['status', n => pill(n.status || '—', n.status === 'Active' ? 'ok' : 'warn'), n => n.status],
      ['pods', n => countCell(n.pods, n.podsUnhealthy), n => n.pods],
      ['workloads', n => countCell(n.workloads, n.workloadsDegraded), n => n.workloads],
      ['warnings', n => (n.warnings ? pill(n.warnings, 'warn') : '0'), n => n.warnings],
    ],
    actions: n => [
      linkButton(t('pods'), routeHash({ view: 'pods', ns: n.name })),
      linkButton(t('events'), routeHash({ view: 'events', ns: n.name })),
      detailButton('Namespace', '', n.name),
    ],
  },
  helm: {
    problem: r => r.status !== 'deployed',
    text: r => [r.namespace, r.name, r.chart, r.status, r.appVersion],
    nsOf: r => r.namespace,
    columns: [
      ['name', r => h('strong', null, r.name), r => r.name],
      ['namespace', r => nsLink(r.namespace), r => r.namespace],
      ['chart', r => (r.chart ? r.chart + (r.chartVersion ? '-' + r.chartVersion : '') : '—'), r => r.chart],
      ['appVersion', r => r.appVersion || '—'],
      ['status', r => pill(r.status, r.status === 'deployed' ? 'ok' : r.status === 'failed' ? 'bad' : 'warn'), r => r.status],
      ['revision', r => r.revision, r => r.revision],
      ['deployed', r => age(r.updated), r => ageOf(r.updated)],
      ['description', r => h('span', { class: 'muted' }, r.description || '')],
    ],
  },
};

// One view per workload kind, drawn like the workloads table minus its kind.
for (const view of Object.keys(VIEW_KIND)) {
  TABLES[view] = Object.assign({}, TABLES.workloads, { columns: TABLES.workloads.columns.filter(([k]) => k !== 'kind') });
}

// usageWithRequest shows usage, with its request and limit in the tooltip.
function usageWithRequest(used, request, limit, fmt) {
  const tip = [request != null ? t('request') + ' ' + fmt(request) : null, limit != null ? t('limit') + ' ' + fmt(limit) : null].filter(Boolean).join(' · ');
  const over = used != null && limit ? used / limit >= 0.9 : false;
  return h('span', { title: tip || null, class: over ? 'status-warn' : null }, used != null ? fmt(used) : '—');
}

// favOf names the favorites list and key a row is starred under: namespaces
// in favs.ns, everything else in favs.obj.
function favOf(spec, it) {
  if (spec.fav) return spec.fav(it);
  return spec.key ? ['obj', spec.key(it)] : null;
}
function isFav(f) {
  return !!f && favs[f[0]].includes(f[1]);
}

function noValue(v) {
  return v == null || Number.isNaN(v);
}
function compareValues(a, b) {
  return typeof a === 'number' && typeof b === 'number' ? a - b : cmp(String(a).toLowerCase(), String(b).toLowerCase());
}

// sortRows puts favorite objects first, then everything in a favorite
// namespace, then the rest: by the column the user picked, or in the
// table's natural order, which also settles ties.
function sortRows(view, spec, rows) {
  const s = state.sort[view];
  const col = s && spec.columns.find(c => c[0] === s.key && c[2]);
  const natural = spec.order || ((a, b) => cmp(a.namespace || '', b.namespace || '') || cmp(a.name, b.name));
  // Rows without a value (no metrics, never run) stay last either way.
  const byColumn = (a, b) => {
    const ea = noValue(a.key);
    const eb = noValue(b.key);
    if (ea || eb) return ea === eb ? 0 : ea ? 1 : -1;
    return Math.sign(compareValues(a.key, b.key)) * s.dir;
  };
  return rows
    .map(it => ({ it, key: col ? col[2](it) : null, rank: isFav(favOf(spec, it)) ? 0 : it.namespace && favs.ns.includes(it.namespace) ? 1 : 2 }))
    .sort((a, b) => a.rank - b.rank || (col ? byColumn(a, b) : 0) || natural(a.it, b.it))
    .map(x => x.it);
}

// Columns where the biggest values are the interesting ones sort that way
// first.
const DESC_FIRST = new Set(['restarts', 'cpu', 'memory', 'count', 'pods', 'workloads', 'warnings', 'failed', 'revision']);

// toggleSort cycles a column through one direction, the other, and back to
// the table's natural order.
function toggleSort(view, key) {
  const first = DESC_FIRST.has(key) ? -1 : 1;
  const cur = state.sort[view];
  if (!cur || cur.key !== key) state.sort[view] = { key, dir: first };
  else if (cur.dir === first) state.sort[view] = { key, dir: -first };
  else delete state.sort[view];
  writeStore('localStorage', 'kartal.sort', JSON.stringify(state.sort));
  renderContent();
  if (state.obj) renderDetail();
}

function matches(words, parts) {
  const text = parts.filter(x => x != null).join(' ').toLowerCase();
  return words.every(w => text.includes(w));
}

function renderTable(view, items, { filtered = true, sortable = true } = {}) {
  const spec = TABLES[view];
  let rows = items;
  if (filtered) {
    const words = state.q.toLowerCase().split(/\s+/).filter(Boolean);
    if (spec.nsOf && state.ns) rows = rows.filter(it => spec.nsOf(it) === state.ns);
    if (words.length) rows = rows.filter(it => matches(words, spec.text(it)));
    if (state.problems && spec.problem) rows = rows.filter(spec.problem);
  }
  if (!rows.length) return emptyState(items.length ? t('noMatch') : t('noItems'));
  rows = sortRows(view, spec, rows);
  const shown = rows.slice(0, state.limit);
  const starred = !!(spec.key || spec.fav);
  const s = state.sort[view];
  return [
    h('table', null,
      h('thead', null, h('tr', null,
        starred ? h('th', { class: 'fav' }) : null,
        spec.columns.map(([k, , sortBy]) => (sortable && sortBy
          ? h('th', { class: 'sortable', title: t('col.' + k), onclick: () => toggleSort(view, k) },
            t('col.' + k), h('span', { class: 'sort-mark' }, s && s.key === k ? (s.dir === 1 ? ' ▲' : ' ▼') : ''))
          : h('th', null, t('col.' + k)))),
        spec.actions ? h('th') : null)),
      h('tbody', null, shown.map(it => {
        const f = favOf(spec, it);
        return h('tr', { class: spec.problem && spec.problem(it) ? 'problem' : null },
          f ? h('td', { class: 'fav' }, starButton(isFav(f), () => toggleFav(f[0], f[1]))) : null,
          spec.columns.map(([, cell]) => h('td', null, cell(it))),
          spec.actions ? h('td', { class: 'actions-cell' }, h('div', { class: 'actions' }, spec.actions(it))) : null);
      }))),
    rows.length > shown.length ? h('div', { class: 'more-note' }, t('showing', shown.length, rows.length), ' ',
      button(t('showMore'), () => { state.limit += 1000; renderContent(); })) : null,
  ];
}

// ---------------------------------------------------------------- overview

function card(label, value, sub, bad, href) {
  return h('a', { class: bad ? 'card bad' : 'card', href },
    h('div', { class: 'label' }, label), h('div', { class: 'value' }, value), h('div', { class: 'muted' }, sub));
}
// capacityCard shows how much of the cluster is in use and how much has been
// promised to pods (their requests): the second is what the scheduler sees.
function capacityCard(label, used, requested, total, fmt, unit = '') {
  const p = pct(used, total);
  return h('div', { class: 'card' },
    h('div', { class: 'label' }, label),
    h('div', { class: 'value' }, p == null ? '—' : p + '%'),
    h('div', { class: 'muted' }, used != null ? t('usedOf', fmt(used), fmt(total)) + unit : total ? t('noMetrics') : '—'),
    bar(used, total),
    requested != null && total ? [
      h('div', { class: 'muted card-sub' }, t('requested') + ': ' + fmt(requested) + unit + ' (' + pct(requested, total) + '%)'),
      bar(requested, total, 'requested'),
    ] : null);
}

// overviewCounts gives the totals on the overview cards: the cluster's, or
// the selected namespace's.
function overviewCounts(summary) {
  if (!state.ns) return summary.counts || {};
  return (state.namespaces || []).find(n => n.name === state.ns) || {};
}

// renderOverview gets only the pods and workloads that need attention; the
// totals come from overviewCounts.
function renderOverview({ summary, nodes, workloads: degraded, pods: unhealthy, events, usage }) {
  const notReady = nodes.filter(n => !n.ready);
  const total = overviewCounts(summary);
  const cap = summary.capacity || {};
  const req = summary.requests || {};
  const use = summary.usage;
  // Nodes and capacity belong to the whole cluster; a user limited to some
  // namespaces sees neither.
  const whole = roleIn('') > 0;
  return [
    h('div', { class: 'cards' },
      whole ? card(t('nodes'), (nodes.length - notReady.length) + ' / ' + nodes.length, t('ready'), notReady.length > 0, routeHash({ view: 'nodes' })) : null,
      card(t('pods'), total.pods == null ? '—' : total.pods, unhealthy.length ? t('nUnhealthy', unhealthy.length) : t('allHealthy'),
        unhealthy.length > 0, routeHash({ view: 'pods', problems: unhealthy.length > 0 })),
      card(t('workloads'), total.workloads == null ? '—' : total.workloads, degraded.length ? t('nDegraded', degraded.length) : t('allReady'),
        degraded.length > 0, routeHash({ view: 'workloads', problems: degraded.length > 0 })),
      card(t('warnings'), events.length, t('warningEvents'), false, routeHash({ view: 'events' })),
      whole ? capacityCard(t('cpu'), use && use.cpuMilli, req.cpuMilli, cap.cpuMilli, cores, ' ' + t('cores')) : null,
      whole ? capacityCard(t('memory'), use && use.memoryBytes, req.memoryBytes, cap.memoryBytes, bytes) : null),
    attentionPanel(nodes.filter(n => !n.ready || (n.pressure || []).length), degraded, unhealthy, total.podsReplaced || 0),
    usage && usage.points && usage.points.length > 1 ? panel(t('clusterUsage'), h('div', { class: 'charts' },
      lineChart({ title: t('cpu'), points: usage.points, value: p => p.cpu, format: cpuUnit, guides: [
        { label: upper(t('allocatable')), value: cap.cpuMilli }, { label: upper(t('requested')), value: req.cpuMilli }] }),
      lineChart({ title: t('memory'), points: usage.points, value: p => p.memory, format: bytes, guides: [
        { label: upper(t('allocatable')), value: cap.memoryBytes }, { label: upper(t('requested')), value: req.memoryBytes }] }))) : null,
    warningsPanel(events),
    summary.errors && summary.errors.length
      ? panel('⚠ ' + t('collectionErrors'), h('ul', null, summary.errors.map(e => h('li', { class: 'mono' }, e))), 'errors')
      : null,
    whole ? panel(t('nodes'), renderTable('nodes', nodes, { filtered: false, sortable: false })) : null,
  ];
}

// attentionPanel lists what is wrong, and notes the pods left behind by
// their controllers, which only want cleaning up.
function attentionPanel(troubledNodes, degraded, unhealthy, replaced) {
  const items = [
    ...troubledNodes.map(n => ({
      rank: 2, level: n.ready ? 'warn' : 'bad', title: t(n.ready ? 'nodePressure' : 'nodeNotReady', n.name),
      detail: (n.pressure || []).join(', '), actions: [detailButton('Node', '', n.name)],
    })),
    ...degraded.map(w => ({
      rank: favRank(w.kind + '/' + w.namespace + '/' + w.name, w.namespace),
      title: w.kind + ' ' + w.namespace + '/' + w.name, detail: t('readyOf', w.ready, w.desired),
      actions: [linkButton(t('pods'), routeHash({ view: 'pods', ns: w.namespace, q: w.name })), detailButton(w.kind, w.namespace, w.name)],
    })),
    ...unhealthy.map(p => ({
      rank: favRank('Pod/' + p.namespace + '/' + p.name, p.namespace),
      title: 'Pod ' + p.namespace + '/' + p.name,
      detail: [podState(p), p.restarts ? t('nRestarts', p.restarts) : ''].filter(Boolean).join(' · '),
      actions: [
        button(t('logs'), () => openDetail({ gvr: KIND_API.Pod, ns: p.namespace, name: p.name }, 'logs')),
        linkButton(t('events'), routeHash({ view: 'events', ns: p.namespace, q: p.name })),
      ],
    })),
  ].sort((a, b) => a.rank - b.rank);
  const shown = items.slice(0, 20);
  const cleanup = 'kubectl delete pod ' + (state.ns ? '-n ' + state.ns : '-A') + ' --field-selector=status.phase=Failed';
  return panel(t('attention'), [
    items.length ? shown.map(it => h('div', { class: 'issue' },
      h('span', { class: 'dot ' + (it.level || 'bad') }),
      h('div', { class: 'what' }, h('div', { class: 'title' }, it.rank < 2 ? '★ ' : '', it.title), it.detail ? h('div', { class: 'detail' }, it.detail) : null),
      h('div', { class: 'actions' }, it.actions))) : h('div', { class: 'ok-note' }, '✓ ' + t('allGood')),
    items.length > shown.length
      ? h('div', { class: 'issue' }, h('a', { class: 'ns-link', href: routeHash({ view: 'pods', problems: true }) }, t('andMore', items.length - shown.length)))
      : null,
    replaced ? h('div', { class: 'issue' },
      h('span', { class: 'dot' }),
      h('div', { class: 'what' },
        h('div', { class: 'title' }, t('replacedPods', replaced)),
        h('div', { class: 'detail' }, t('replacedHint')),
        h('code', { class: 'mono detail' }, cleanup)),
      h('div', { class: 'actions' },
        button(t('copy'), () => copyText(cleanup)),
        linkButton(t('pods'), routeHash({ view: 'pods', q: 'Failed' })))) : null,
  ]);
}

function warningsPanel(events) {
  if (!events.length) return null;
  const recent = events.slice().sort((a, b) => when(b.lastSeen) - when(a.lastSeen)).slice(0, 8);
  return panel(t('recentWarnings'), recent.map(e => h('div', { class: 'issue' },
    h('span', { class: 'dot warn' }),
    h('div', { class: 'what' },
      h('div', { class: 'title' }, e.reason, ' · ', objectLink(e.namespace, e.object), h('span', { class: 'muted' }, ' · ' + e.namespace)),
      h('div', { class: 'detail' }, e.message)),
    h('span', { class: 'muted' }, '×' + e.count + ' · ', age(e.lastSeen)))));
}

// ---------------------------------------------------------------- resource browser

function renderResources({ type, items }) {
  const d = state.discovery;
  const words = state.q.toLowerCase().split(/\s+/).filter(Boolean);
  if (!type) {
    const groups = new Map();
    for (const r of d.resources) {
      if (!matches(words, [r.kind, r.resource, r.group])) continue;
      const g = r.group || 'core';
      if (!groups.has(g)) groups.set(g, []);
      groups.get(g).push(r);
    }
    const out = [];
    if (d.errors.length) out.push(panel('⚠ ' + t('discoveryErrors'), h('ul', null, d.errors.map(e => h('li', { class: 'mono' }, e))), 'errors'));
    for (const [g, list] of groups) {
      out.push(h('div', { class: 'group-title' }, g));
      out.push(h('div', { class: 'resource-grid' }, list.map(r => h('a', { class: 'row', href: routeHash({ view: 'resources', rest: [g, r.version, r.resource] }) },
        h('span', { class: 'name' }, r.kind), h('span', { class: 'muted mono' }, r.resource),
        r.namespaced ? null : h('span', { class: 'badge' }, t('clusterScoped'))))));
    }
    return out.length ? out : emptyState(t('noMatch'));
  }
  const gvr = [type.group || 'core', type.version, type.resource].join('/');
  const rows = items.filter(it => matches(words, [it.namespace, it.name]));
  const shown = rows.slice(0, state.limit);
  return [
    h('div', { class: 'toolbar' }, linkButton('← ' + t('allTypes'), routeHash({ view: 'resources' })),
      h('strong', null, type.kind), h('span', { class: 'muted mono' }, gvr)),
    rows.length ? h('table', null,
      h('thead', null, h('tr', null, h('th', null, t('col.name')), type.namespaced ? h('th', null, t('col.namespace')) : null, h('th', null, t('col.age')), h('th'))),
      h('tbody', null, shown.map(it => h('tr', null,
        h('td', null, h('button', { type: 'button', class: 'link-button', onclick: () => openDetail({ gvr, ns: it.namespace || '', name: it.name, kind: type.kind }) },
          h('strong', null, it.name))),
        type.namespaced ? h('td', null, nsLink(it.namespace)) : null,
        h('td', null, age(it.createdAt)),
        h('td', { class: 'actions-cell' }, h('div', { class: 'actions' },
          button(t('details'), () => openDetail({ gvr, ns: it.namespace || '', name: it.name, kind: type.kind })))))))) : emptyState(items.length ? t('noMatch') : t('noItems')),
    rows.length > shown.length ? h('div', { class: 'more-note' }, t('showing', shown.length, rows.length), ' ',
      button(t('showMore'), () => { state.limit += 1000; renderContent(); })) : null,
  ];
}

// ---------------------------------------------------------------- alerts and audit

// goDuration shortens a Go duration: "2m0s" is "2m", "1h0m0s" is "1h".
function goDuration(s) {
  return String(s || '').replace(/(\d+[hm])0s$/, '$1').replace(/(\d+h)0m$/, '$1');
}

function renderAlerts(st) {
  if (!st.enabled) return emptyState(t('alertsOff'));
  const words = state.q.toLowerCase().split(/\s+/).filter(Boolean);
  const wanted = a => matches(words, [a.cluster, a.kind, t('alert.' + a.kind), a.namespace, a.object, a.detail]);
  const active = st.active.filter(wanted);
  const recent = st.recent.filter(wanted);
  const notify = st.channels.length > 0;
  const alertRow = a => h('tr', { class: a.severity === 'critical' ? 'problem' : null },
    h('td', null, pill(t(a.severity), a.severity === 'critical' ? 'bad' : 'warn')),
    h('td', null, t('alert.' + a.kind)),
    h('td', null, a.cluster || h('a', { href: routeHash({ view: 'uptime' }) }, t('uptime'))),
    h('td', null, a.namespace ? a.namespace + '/' : '', alertObject(a)),
    h('td', null, a.detail),
    h('td', null, age(a.since)),
    // Without a channel nothing is sent, so there is nothing to show.
    notify ? h('td', null, a.notified ? pill('✓ ' + t('notified'), 'ok') : h('span', { class: 'muted' }, t('waitingNotify'))) : null);
  return [
    panel(t('alertsChannels'), h('div', { class: 'issue' },
      h('div', { class: 'what' },
        st.channels.length ? h('div', { class: 'chips' }, st.channels.map(c => h('span', { class: 'chip' }, c))) : h('div', { class: 'status-warn' }, t('noChannels')),
        h('div', { class: 'detail' }, t('alertsAfter', goDuration(st.after)))),
      h('div', { class: 'actions' },
        st.channels.length ? actionButton(t('testNotify'), testNotification, { role: 'admin', cap: null, where: null }) : null,
        actionButton(t('mailSettings'), mailDialog, { role: 'admin', cap: null, where: null })))),
    panel(t('alertsActive') + ' (' + st.active.length + ')', active.length ? h('table', null,
      h('thead', null, h('tr', null, ['severity', 'problem', 'cluster', 'object', 'detail', 'since'].concat(notify ? ['notified'] : []).map(k => h('th', null, t('col.' + k))))),
      h('tbody', null, active.map(alertRow))) : h('div', { class: 'ok-note' }, '✓ ' + t('noAlerts'))),
    recent.length ? panel(t('alertsRecent'), h('table', null,
      h('thead', null, h('tr', null, ['time', 'problem', 'cluster', 'object', 'detail'].map(k => h('th', null, t('col.' + k))))),
      h('tbody', null, recent.slice(0, 100).map(a => h('tr', null,
        h('td', null, age(a.resolved || a.since), ' ', h('span', { class: a.resolved ? 'status-ok' : 'status-bad' }, a.resolved ? t('resolvedAt') : t('startedAt'))),
        h('td', null, t('alert.' + a.kind)),
        h('td', null, a.cluster || t('uptime')),
        h('td', null, a.namespace ? a.namespace + '/' : '', a.object),
        h('td', null, a.detail)))))) : null,
    st.deliveries.length ? panel(t('deliveries'), h('table', null,
      h('thead', null, h('tr', null, ['time', 'channel', 'title', 'result'].map(k => h('th', null, t('col.' + k))))),
      h('tbody', null, st.deliveries.map(d => h('tr', { class: d.error ? 'problem' : null },
        h('td', null, age(d.time)), h('td', null, d.channel), h('td', null, d.title),
        h('td', null, d.error ? h('span', { class: 'status-bad' }, d.error) : pill(t('ok'), 'ok'))))))) : null,
  ];
}

// alertObject links an alert to the object when it is in this cluster.
function alertObject(a) {
  if (a.cluster !== state.cluster) return a.object;
  // A watched metric's alert leads to its chart.
  if (a.kind === 'MetricLimit') return h('a', { class: 'ns-link', href: routeHash({ view: 'appmetrics', ns: a.namespace, q: a.object }) }, a.object);
  const kinds = {
    NodeNotReady: 'Node', NodePressure: 'Node', PodFailing: 'Pod', JobFailed: 'Job', VolumeClaimUnbound: 'PersistentVolumeClaim',
    VolumeFilling: 'PersistentVolumeClaim', CertificateExpiring: 'Secret',
  };
  let kind = kinds[a.kind];
  let name = a.object;
  if (a.kind === 'WorkloadDegraded') [kind, name] = a.object.split('/');
  const gvr = KIND_API[kind];
  if (!gvr) return a.object;
  return h('button', { type: 'button', class: 'link-button', onclick: () => openDetail({ gvr, ns: kind === 'Node' ? '' : a.namespace, name }) }, a.object);
}

async function testNotification() {
  try {
    const res = await api('alerts/test', { method: 'POST' });
    toast(t('testSent', Object.entries(res).map(([k, v]) => k + ': ' + v).join(', ')), Object.values(res).some(v => v !== 'ok'));
    refresh();
  } catch (e) {
    if (e.status !== 401) toast(e.message, true);
  }
}

// modal shows content over the page until the returned function closes it;
// Escape or a click beside it closes it too.
function modal(content) {
  const onKey = e => {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      close();
    }
  };
  const overlay = h('div', { class: 'overlay', onclick: e => { if (e.target === overlay) close(); } }, content);
  function close() {
    overlay.remove();
    document.removeEventListener('keydown', onKey, true);
  }
  document.body.append(overlay);
  document.addEventListener('keydown', onKey, true);
  return close;
}

// mailDialog lets an admin set up the e-mail channel and try it before
// saving. The password is never sent back: an empty field keeps it.
async function mailDialog() {
  let v;
  try {
    v = await api('settings/email');
  } catch (e) {
    if (e.status !== 401) toast(e.message, true);
    return;
  }
  const fixed = v.fixed;
  const field = (label, input, help) => h('label', { class: 'field' }, h('span', null, label), input,
    help ? h('span', { class: 'muted small-text' }, help) : null);
  const enabled = h('input', { type: 'checkbox', checked: v.enabled, disabled: fixed });
  const addr = h('input', { type: 'text', value: v.addr, placeholder: 'smtp.example.org:587', disabled: fixed, autocomplete: 'off', spellcheck: 'false' });
  const from = h('input', { type: 'text', value: v.from, placeholder: 'kartal@example.org', disabled: fixed, autocomplete: 'off', spellcheck: 'false' });
  const to = h('textarea', { rows: '2', value: v.to.join(', '), placeholder: 'ops@example.org, team@example.org', disabled: fixed, spellcheck: 'false' });
  const user = h('input', { type: 'text', value: v.username, disabled: fixed, autocomplete: 'off', spellcheck: 'false' });
  const pass = h('input', { type: 'password', placeholder: v.passwordSet ? '••••••••' : '', disabled: fixed, autocomplete: 'new-password' });
  const clear = v.passwordSet && !fixed ? h('input', { type: 'checkbox', onchange: e => { pass.disabled = e.target.checked; } }) : null;
  const status = h('div', { class: 'form-status', role: 'status' });
  const say = (text, kind) => {
    status.className = kind ? 'form-status ' + kind : 'form-status';
    status.textContent = text;
  };
  const change = () => {
    const c = { enabled: enabled.checked, addr: addr.value, from: from.value, to: [to.value], username: user.value };
    if (clear && clear.checked) c.password = '';
    else if (pass.value) c.password = pass.value;
    return c;
  };
  const buttons = [];
  const busy = on => buttons.forEach(b => { b.disabled = on; });
  const test = async () => {
    busy(true);
    say(t('sending'));
    try {
      say((await api('settings/email/test', { method: 'POST', body: change() })).message, 'ok');
    } catch (e) {
      if (e.status !== 401) say(e.message, 'bad');
    }
    busy(false);
  };
  const form = h('form', {
    class: 'dialog wide',
    onsubmit: async e => {
      e.preventDefault();
      if (fixed) return;
      busy(true);
      try {
        await api('settings/email', { method: 'PUT', body: change() });
        close();
        toast(t('mailSaved'));
        refresh();
      } catch (err) {
        if (err.status !== 401) say(err.message, 'bad');
        busy(false);
      }
    },
  },
  h('h2', null, t('mailSettings')),
  fixed ? h('p', { class: 'note' }, t('mailFixed'))
    : h('p', { class: v.where ? 'note' : 'note warn' }, v.where ? t('mailWhere', v.where) : t('mailNotKept')),
  v.loadError ? h('p', { class: 'note bad' }, t('mailLoadError', v.loadError)) : null,
  h('label', { class: 'check-line' }, enabled, t('mailEnabled')),
  field(t('mailServer'), addr, t('mailServerHelp')),
  field(t('mailFrom'), from),
  field(t('mailTo'), to, t('mailToHelp')),
  h('div', { class: 'field-row' },
    field(t('mailUser'), user),
    field(t('mailPassword'), pass, v.passwordSet && !fixed ? t('mailPasswordKeep') : null)),
  clear ? h('label', { class: 'check-line' }, clear, t('mailPasswordClear')) : null,
  status,
  h('div', { class: 'dialog-actions' },
    buttons[0] = button(t('sendTest'), test),
    h('span', { class: 'grow' }),
    buttons[1] = button(fixed ? t('close') : t('cancel'), () => close()),
    fixed ? null : (buttons[2] = h('button', { type: 'submit', class: 'btn primary' }, t('save')))));
  const close = modal(form);
  (fixed ? buttons[1] : addr).focus();
}

function renderAudit(items) {
  const words = state.q.toLowerCase().split(/\s+/).filter(Boolean);
  const rows = items.filter(e => matches(words, [e.user, e.action, e.cluster, e.namespace, e.object, e.detail, e.error]));
  if (!items.length) return [emptyState(t('auditEmpty')), h('div', { class: 'more-note' }, t('auditHint'))];
  return [
    h('table', null,
      h('thead', null, h('tr', null, ['time', 'user', 'action', 'cluster', 'object', 'detail', 'result'].map(k => h('th', null, t('col.' + k))))),
      h('tbody', null, rows.slice(0, state.limit).map(e => h('tr', { class: e.ok ? null : 'problem' },
        h('td', null, age(e.time)),
        h('td', null, h('strong', null, e.user), h('span', { class: 'muted' }, ' · ' + t('role.' + e.role))),
        h('td', null, e.action),
        h('td', null, e.cluster || '—'),
        h('td', null, e.object, e.namespace ? h('span', { class: 'muted' }, ' · ' + e.namespace) : null),
        h('td', null, mono(e.detail || '')),
        h('td', null, e.ok ? pill(t('ok'), 'ok') : h('span', { class: 'status-bad' }, e.error)))))),
    h('div', { class: 'more-note' }, t('auditHint')),
  ];
}

// ---------------------------------------------------------------- changes and versions

// shortImage drops an image's registry and path and shortens its digest.
function shortImage(image) {
  return String(image).split('/').pop().replace(/@sha256:([0-9a-f]{12})[0-9a-f]+$/, '@$1');
}

// imageChange shows the images that changed: "web:1 → web:2".
function imageChange(from, to) {
  const a = from ? from.split(', ') : [];
  const b = to ? to.split(', ') : [];
  const gone = a.filter(x => !b.includes(x));
  const came = b.filter(x => !a.includes(x));
  const moved = gone.length || came.length;
  const list = xs => mono(xs.map(shortImage).join(', ') || '—');
  return h('span', { title: (from || '—') + ' → ' + (to || '—') }, list(moved ? gone : a), ' → ', list(moved ? came : b));
}

// changeText says what changed and, where that helps, from what to what.
function changeText(c) {
  const word = t('what.' + c.what);
  const label = h('span', { class: 'change-what' }, word === 'what.' + c.what ? c.what : word);
  switch (c.what) {
    case 'image': return [label, ' ', imageChange(c.from, c.to)];
    case 'replicas': return [label, ' ', mono(c.from + ' → ' + c.to)];
    case 'schedule': return [label, ' ', mono(c.from), ' → ', mono(c.to)];
    case 'scale': return c.to ? [label, ' ', mono('→ ' + c.to)] : label;
    case 'rollback': return c.to ? [label, ' ', mono('→ #' + c.to)] : label;
    case 'exec': return [label, ' ', mono(c.to || '')];
    case 'not-ready': return c.to ? [label, ' ', h('span', { class: 'muted' }, c.to)] : label;
    case 'created': case 'deleted': {
      const v = c.to || c.from;
      if (!v) return label;
      return [label, ' ', h('span', { class: 'muted', title: v }, c.kind === 'CronJob' ? v : v.split(', ').map(shortImage).join(', '))];
    }
    default: return label;
  }
}

// changeObject names what changed, as a link while it is still there.
function changeObject(c) {
  const gvr = KIND_API[c.kind];
  const gone = c.what === 'deleted' || c.what === 'delete';
  return [
    gvr && !gone
      ? h('button', { type: 'button', class: 'link-button', onclick: () => openDetail({ gvr, ns: c.namespace || '', name: c.name }) }, h('strong', null, c.name))
      : h('strong', null, c.name),
    h('span', { class: 'muted' }, ' · ' + c.kind + (c.namespace && !state.ns ? ' · ' + c.namespace : '')),
  ];
}

function changesTable(items, { object = true } = {}) {
  // Who made a change is shown to operators only, so the column may be empty.
  const by = items.some(c => c.by);
  const cols = ['time'].concat(object ? ['object'] : [], ['change'], by ? ['by'] : []);
  return h('table', object ? null : { class: 'compact' },
    h('thead', null, h('tr', null, cols.map(k => h('th', null, t('col.' + k))))),
    h('tbody', null, items.map(c => h('tr', { class: c.what === 'not-ready' ? 'problem' : null },
      h('td', null, age(c.time)),
      object ? h('td', null, changeObject(c)) : null,
      h('td', null, changeText(c)),
      by ? h('td', null, c.by ? h('strong', null, c.by) : h('span', { class: 'muted' }, '—')) : null))));
}

function renderChanges(items) {
  if (!items.length) return [emptyState(t('noChanges2')), h('div', { class: 'more-note' }, t('changesHint'))];
  const words = state.q.toLowerCase().split(/\s+/).filter(Boolean);
  const rows = items.filter(c => matches(words, [c.kind, c.name, c.namespace, c.what, t('what.' + c.what), c.from, c.to, c.by]));
  if (!rows.length) return emptyState(t('noMatch'));
  const shown = rows.slice(0, state.limit);
  return [
    changesTable(shown),
    rows.length > shown.length ? h('div', { class: 'more-note' }, t('showing', shown.length, rows.length), ' ',
      button(t('showMore'), () => { state.limit += 1000; renderContent(); })) : null,
    h('div', { class: 'more-note' }, t('changesHint')),
  ];
}

// renderReleases puts every app's images side by side, a column per cluster.
// An app whose versions differ between clusters is marked; one missing from
// a cluster shows a dash there.
function renderReleases(items) {
  if (!items.length) return [emptyState(t('noItems')), h('div', { class: 'more-note' }, t('versionsHint'))];
  const known = (state.clusters || []).map(c => c.name);
  const clusters = [...new Set(known.concat(items.map(r => r.cluster)))].filter(n => items.some(r => r.cluster === n));
  const version = r => (r.images || []).slice().sort().join(', ');
  const apps = new Map();
  for (const r of items) {
    const key = r.namespace + '/' + r.kind + '/' + r.name;
    if (!apps.has(key)) apps.set(key, { namespace: r.namespace, kind: r.kind, name: r.name, in: {} });
    apps.get(key).in[r.cluster] = r;
  }
  const words = state.q.toLowerCase().split(/\s+/).filter(Boolean);
  let rows = [...apps.values()];
  for (const app of rows) {
    const found = Object.values(app.in);
    app.differs = new Set(found.map(version)).size > 1;
    app.missing = clusters.length > 1 && found.length < clusters.length;
    app.text = [app.namespace, app.kind, app.name].concat(found.flatMap(r => [r.cluster].concat(r.images || [])));
  }
  rows = rows.filter(app => matches(words, app.text) && (!state.problems || app.differs || app.missing));
  if (!rows.length) return emptyState(t('noMatch'));
  rows.sort((a, b) => a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name) || a.kind.localeCompare(b.kind));
  const shown = rows.slice(0, state.limit);
  // A cell opens the app in its cluster; the versions stay in view.
  const cell = (app, cluster) => {
    const r = app.in[cluster];
    if (!r) return h('td', { class: 'release-cell' }, h('span', { class: 'muted' }, '—'));
    const obj = objParam({ gvr: KIND_API[r.kind], ns: r.namespace, name: r.name });
    return h('td', { class: 'release-cell' },
      h('a', { href: routeHash({ cluster, view: 'releases', ns: '', q: state.q, problems: state.problems, obj }), title: (r.images || []).join('\n') },
        (r.images || []).map(i => h('div', { class: 'mono' }, shortImage(i)))),
      h('div', { class: r.ready < r.desired ? 'status-warn' : 'muted' }, r.ready + '/' + r.desired + ' ' + t('ready')));
  };
  return [
    h('table', null,
      h('thead', null, h('tr', null, h('th', null, t('col.app')), h('th', null, t('col.namespace')), clusters.map(c => h('th', null, c)))),
      h('tbody', null, shown.map(app => h('tr', { class: app.differs ? 'differs' : null },
        h('td', null, h('strong', null, app.name), h('span', { class: 'muted' }, ' · ' + app.kind),
          app.differs ? h('span', { class: 'badge warn', title: t('onlyDifferences') }, '≠') : null),
        h('td', null, app.namespace),
        clusters.map(c => cell(app, c)))))),
    rows.length > shown.length ? h('div', { class: 'more-note' }, t('showing', shown.length, rows.length), ' ',
      button(t('showMore'), () => { state.limit += 1000; renderContent(); })) : null,
    h('div', { class: 'more-note' }, t('versionsHint')),
  ];
}

// ---------------------------------------------------------------- URL checks

// hourBars draws a check's last 24 hours, a bar an hour.
function hourBars(hours) {
  return h('div', { class: 'hour-bars' }, hours.map(x => {
    const from = new Date(when(x.start)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const level = !x.checks ? 'none' : !x.failed ? 'ok' : x.failed * 10 <= x.checks ? 'warn' : 'bad';
    return h('span', { class: 'hour ' + level, title: x.checks ? t('hourFailed', from, x.failed, x.checks) : t('hourNone', from) });
  }));
}

function renderUptime({ checks, where, loadError }) {
  const head = panel(null, h('div', { class: 'issue' },
    h('div', { class: 'what' },
      h('div', { class: 'detail' }, t('checksHint')),
      canEverywhere('admin') ? h('div', { class: where ? 'detail' : 'detail status-warn' }, where ? t('mailWhere', where) : t('mailNotKept')) : null,
      loadError ? h('div', { class: 'detail status-bad' }, t('mailLoadError', loadError)) : null),
    h('div', { class: 'actions' }, actionButton(t('addCheck'), () => checkDialog(), { role: 'admin', cap: null, where: null }))));
  if (!checks.length) return [head, emptyState(t('noChecks'))];
  const words = state.q.toLowerCase().split(/\s+/).filter(Boolean);
  const rows = checks.filter(c => matches(words, [c.name, c.url, c.last && c.last.error]));
  if (!rows.length) return [head, emptyState(t('noMatch'))];
  const admin = canEverywhere('admin');
  const status = c => {
    if (!c.last) return pill(t('check.waiting'), 'warn');
    return [pill(t(c.last.ok ? 'check.up' : 'check.down'), c.last.ok ? 'ok' : 'bad'),
      c.since ? h('div', { class: 'muted small-text' }, t('upFor', ago(c.since))) : null];
  };
  const uptime = c => {
    if (c.uptime == null) return '—';
    const v = Math.floor(c.uptime * 10) / 10;
    return h('span', { class: v >= 99.5 ? null : v >= 95 ? 'status-warn' : 'status-bad' }, v + '%');
  };
  return [
    head,
    h('table', null,
      h('thead', null, h('tr', null, ['status', 'check', 'last24h', 'uptime', 'response', 'certificate'].map(k => h('th', null, t('col.' + k))),
        admin ? h('th') : null)),
      h('tbody', null, rows.map(c => h('tr', { class: c.last && !c.last.ok ? 'problem' : null },
        h('td', null, status(c)),
        h('td', { class: 'check-cell' },
          h('strong', null, c.name),
          h('div', null, h('a', { class: 'check-url mono', href: c.url, target: '_blank', rel: 'noopener noreferrer' }, c.url)),
          c.last && !c.last.ok ? h('div', { class: 'status-bad small-text' }, c.last.error) : null),
        h('td', null, hourBars(c.hours)),
        h('td', null, uptime(c)),
        h('td', { title: c.avgMs ? 'Ø ' + c.avgMs + ' ms' : null }, c.last ? c.last.ms + ' ms' : '—'),
        h('td', { title: c.last && c.last.cert ? c.last.cert.subject + (c.last.cert.issuer ? ' · ' + c.last.cert.issuer : '') : null },
          c.last && c.last.cert ? expiresCell(c.last.cert.notAfter) : '—'),
        admin ? h('td', { class: 'actions-cell' }, h('div', { class: 'actions' },
          button(t('edit'), () => checkDialog(c)),
          button(t('removeCheck'), () => removeCheck(c), 'danger'))) : null)))),
  ];
}

async function removeCheck(c) {
  const ok = await ask({ title: t('removeCheckTitle'), message: t('removeCheckConfirm', c.name), confirm: t('removeCheck'), danger: true });
  if (!ok) return;
  try {
    await api('checks/' + enc(c.id), { method: 'DELETE' });
    toast(t('checkRemoved'));
    refresh();
  } catch (e) {
    if (e.status !== 401) toast(e.message, true);
  }
}

// checkDialog adds a check, or changes c; it can try the address first.
function checkDialog(c) {
  const field = (label, input, help) => h('label', { class: 'field' }, h('span', null, label), input,
    help ? h('span', { class: 'muted small-text' }, help) : null);
  const name = h('input', { type: 'text', value: c ? c.name : '', maxlength: '100', autocomplete: 'off', spellcheck: 'false' });
  const url = h('input', { type: 'text', inputmode: 'url', value: c ? c.url : '', placeholder: 'portal.example.org/healthz', autocomplete: 'off', spellcheck: 'false' });
  const every = c ? c.interval : 60;
  // A check set through the API may ask at another interval; it stays.
  const intervals = [...new Set([30, 60, 120, 300, 600, 1800, 3600, every])].sort((a, b) => a - b);
  const interval = h('select', null, intervals.map(s => h('option', { value: String(s), selected: s === every }, span(s * 1000))));
  const timeout = h('input', { type: 'number', min: '1', max: '60', value: String(c ? c.timeout : 10) });
  const status = h('input', { type: 'number', min: '100', max: '599', value: c && c.status ? String(c.status) : '', placeholder: '200' });
  const contains = h('input', { type: 'text', value: (c && c.contains) || '', maxlength: '200', spellcheck: 'false' });
  const insecure = h('input', { type: 'checkbox', checked: !!(c && c.insecure) });
  const note = h('div', { class: 'form-status', role: 'status' });
  const say = (text, kind) => {
    note.className = kind ? 'form-status ' + kind : 'form-status';
    note.textContent = text;
  };
  const body = () => ({
    name: name.value, url: url.value, interval: Number(interval.value), timeout: Number(timeout.value) || 0,
    status: Number(status.value) || 0, contains: contains.value, insecure: insecure.checked,
  });
  const buttons = [];
  const busy = on => buttons.forEach(b => { b.disabled = on; });
  const tryIt = async () => {
    busy(true);
    say(t('trying'));
    try {
      const r = await api('checks/try', { method: 'POST', body: body() });
      const cert = r.cert ? ' · ' + t('certUntil', new Date(when(r.cert.notAfter)).toLocaleDateString()) : '';
      say((r.ok ? t('tryOK', r.status, r.ms) : '✗ ' + r.error) + cert, r.ok ? 'ok' : 'bad');
    } catch (e) {
      if (e.status !== 401) say(e.message, 'bad');
    }
    busy(false);
  };
  const form = h('form', {
    class: 'dialog wide',
    onsubmit: async e => {
      e.preventDefault();
      busy(true);
      try {
        await api(c ? 'checks/' + enc(c.id) : 'checks', { method: c ? 'PUT' : 'POST', body: body() });
        close();
        toast(t('checkSaved'));
        refresh();
      } catch (err) {
        if (err.status !== 401) say(err.message, 'bad');
        busy(false);
      }
    },
  },
  h('h2', null, c ? t('editCheck') : t('newCheck')),
  field(t('checkURL'), url, t('checkURLHelp')),
  field(t('checkName'), name),
  h('div', { class: 'field-row' }, field(t('checkInterval'), interval), field(t('checkTimeout'), timeout)),
  h('div', { class: 'field-row' }, field(t('checkStatus'), status, t('checkStatusHelp')), field(t('checkContains'), contains)),
  h('label', { class: 'check-line' }, insecure, t('checkInsecure')),
  note,
  h('div', { class: 'dialog-actions' },
    buttons[0] = button(t('tryCheck'), tryIt),
    h('span', { class: 'grow' }),
    buttons[1] = button(t('cancel'), () => close()),
    buttons[2] = h('button', { type: 'submit', class: 'btn primary' }, t('save'))));
  const close = modal(form);
  url.focus();
}

// ---------------------------------------------------------------- app metrics

// metricValue writes a watched value for people, going by what the
// metric's name says it measures.
function metricValue(w, v) {
  if (v == null || !Number.isFinite(v)) return '—';
  const per = w.rate ? '/s' : '';
  if (/_bytes(_total)?$/.test(w.metric)) return bytes(Math.max(0, v)) + per;
  if (/_seconds$/.test(w.metric) && !w.rate) return v < 1 ? +(v * 1000).toPrecision(3) + ' ms' : +v.toPrecision(3) + ' s';
  return compact(v) + per;
}
function compact(v) {
  const a = Math.abs(v);
  if (a >= 1e9) return +(v / 1e9).toFixed(2) + 'G';
  if (a >= 1e6) return +(v / 1e6).toFixed(2) + 'M';
  if (a >= 1e4) return +(v / 1e3).toFixed(1) + 'k';
  if (a >= 100) return String(Math.round(v));
  return String(+v.toPrecision(3));
}
// labelsText writes labels the way Prometheus does: {code="500"}.
function labelsText(labels) {
  const keys = Object.keys(labels || {}).sort();
  return keys.length ? '{' + keys.map(k => k + '="' + labels[k] + '"').join(', ') + '}' : '';
}
// labelsInput and parseLabelsInput are labels as people type them:
// code=500, method=GET.
function labelsInput(labels) {
  return Object.keys(labels || {}).sort().map(k => k + '=' + labels[k]).join(', ');
}
function parseLabelsInput(text) {
  const out = {};
  for (const part of text.split(',').map(s => s.trim()).filter(Boolean)) {
    const m = /^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"?(.*?)"?$/.exec(part);
    if (!m) return null;
    out[m[1]] = m[2];
  }
  return out;
}
function watchPath(ns, id) {
  return clusterPath() + '/namespaces/' + enc(ns) + '/watches' + (id ? '/' + enc(id) : '');
}
// targetLink opens the workload or pod a watch reads.
function targetLink(ns, target) {
  const [kind, name] = target.split('/');
  const gvr = KIND_API[kind];
  return gvr ? h('button', { type: 'button', class: 'link-button', onclick: () => openDetail({ gvr, ns, name }) }, target) : target;
}

function renderAppMetrics({ watches, where, loadError }) {
  const hours = state.watchHours || 1;
  const head = panel(null, h('div', { class: 'issue' },
    h('div', { class: 'what' },
      h('div', { class: 'detail' }, t('watchesHint')),
      canIn('operator', state.ns) ? h('div', { class: where ? 'detail' : 'detail status-warn' }, where ? t('mailWhere', where) : t('mailNotKept')) : null,
      loadError ? h('div', { class: 'detail status-bad' }, t('mailLoadError', loadError)) : null),
    h('div', { class: 'actions' },
      agentAllows('scrape') ? button(t('findSources'), findSources, 'primary') : null,
      [1, 6, 24].map(n => h('button', {
        type: 'button', class: n === hours ? 'chip active' : 'chip',
        onclick: () => {
          state.watchHours = n;
          state.data = null;
          renderContent();
          refresh();
        },
      }, n === 1 ? t('last1h') : n === 6 ? t('last6h') : t('last24h'))))));
  const found = sourcesPanel();
  if (!watches.length) return [head, found, found ? null : emptyState(t('noWatches'))];
  const words = state.q.toLowerCase().split(/\s+/).filter(Boolean);
  const rows = watches.filter(w => matches(words, [w.name, w.metric, w.target, w.namespace, labelsText(w.labels)]));
  return [head, found, rows.length ? h('div', { class: 'watch-grid' }, rows.map(watchCard)) : emptyState(t('noMatch'))];
}

// Sources are the workloads found to expose metrics, kept while the page
// shows the same cluster and namespace. Finding them asks a pod of every
// workload, so it is done only on request.
function sourcesKey() { return state.cluster + '|' + state.ns; }

async function findSources() {
  const key = sourcesKey();
  state.sources = { key, loading: true };
  renderContent();
  try {
    const value = await api(clusterPath() + '/metric-sources' + (state.ns ? '?namespace=' + enc(state.ns) : ''));
    if (state.sources && state.sources.key === key) state.sources = { key, value };
  } catch (e) {
    if (e.status === 401) return;
    if (state.sources && state.sources.key === key) state.sources = { key, error: e };
  }
  if (state.view === 'appmetrics') renderContent();
}

function sourcesPanel() {
  const s = state.sources;
  if (!s || s.key !== sourcesKey()) return null;
  if (s.loading) return panel(t('findSources'), h('div', { class: 'empty-note' }, t('findingSources')));
  if (s.error) return errorPanel(s.error);
  const { sources, tried, unfinished } = s.value;
  const words = state.q.toLowerCase().split(/\s+/).filter(Boolean);
  const rows = sources.filter(x => matches(words, [x.namespace, x.workload, x.pod]));
  return panel(t('sourcesTitle', sources.length), [
    h('div', { class: 'issue' }, h('div', { class: 'what' },
      h('div', { class: 'detail' }, sources.length ? t('sourcesHint') : t('noSources', tried)),
      unfinished ? h('div', { class: 'detail status-warn' }, t('sourcesUnfinished')) : null)),
    rows.length ? h('table', { class: 'flat' },
      h('thead', null, h('tr', null, ['namespace', 'workload', 'address', 'metrics'].map(k => h('th', null, t('col.' + k))), h('th'))),
      h('tbody', null, rows.map(x => h('tr', null,
        h('td', null, nsLink(x.namespace)),
        h('td', null, h('strong', null, x.workload)),
        h('td', { class: 'mono' }, ':' + x.port + x.path),
        h('td', null, x.metrics),
        h('td', { class: 'actions-cell' }, button(t('openMetrics'), () => openSource(x))))))) : null,
  ], 'sources');
}

// pendingScrape is where the next Metrics tab opened from a source reads,
// instead of the port it would pick itself.
let pendingScrape = null;

function openSource(x) {
  let [kind, name] = x.workload.split('/');
  // Only these kinds have the tab; for the others, such as a Job's pod or a
  // node's static pod, the pod itself is opened.
  if (!['Deployment', 'StatefulSet', 'DaemonSet'].includes(kind)) [kind, name] = ['Pod', x.pod];
  pendingScrape = { ns: x.namespace, name, pod: x.pod, port: x.port, path: x.path };
  openDetail({ gvr: KIND_API[kind], ns: x.namespace, name }, 'scrape');
}

function watchCard(w) {
  const guides = [];
  if (w.above != null) guides.push({ label: upper(t('limitAbove')), value: w.above });
  if (w.below != null) guides.push({ label: upper(t('limitBelow')), value: w.below });
  const what = [t('agg.' + w.aggregate), w.metric + labelsText(w.labels), w.rate ? t('perSecond') : null].filter(Boolean).join(' · ');
  return h('section', { class: w.past ? 'watch-card past' : 'watch-card' },
    lineChart({ title: w.name, points: w.points || [], value: p => p.v, format: v => metricValue(w, v), guides, empty: w.error ? '—' : t('noPointsYet') }),
    h('div', { class: 'watch-meta' },
      h('div', null, nsLink(w.namespace), ' · ', targetLink(w.namespace, w.target), w.pods ? h('span', { class: 'muted' }, ' · ' + t('podsRead', w.pods)) : null),
      h('div', { class: 'mono muted small-text', title: ':' + w.port + w.path }, what)),
    w.error ? h('div', { class: 'status-bad small-text' }, w.error) : null,
    canIn('operator', w.namespace) ? h('div', { class: 'actions' },
      button(t('edit'), () => watchDialog({ watch: w })),
      button(t('removeWatch'), () => removeWatch(w), 'danger')) : null);
}

async function removeWatch(w) {
  const ok = await ask({ title: t('removeWatchTitle'), message: t('removeWatchConfirm', w.name), confirm: t('removeWatch'), danger: true });
  if (!ok) return;
  try {
    await api(watchPath(w.namespace, w.id), { method: 'DELETE' });
    toast(t('watchRemoved'));
    refresh();
  } catch (e) {
    if (e.status !== 401) toast(e.message, true);
  }
}

// podOwner is the workload whose pods a pod is one of, as the agent names
// it: a ReplicaSet's pods belong to its Deployment.
function podOwner(pod) {
  const m = pod.metadata || {};
  const o = (m.ownerReferences || []).find(x => x.controller);
  if (!o) return '';
  const hash = (m.labels || {})['pod-template-hash'];
  if (o.kind === 'ReplicaSet' && hash && o.name.endsWith('-' + hash)) return 'Deployment/' + o.name.slice(0, -hash.length - 1);
  return ['Deployment', 'StatefulSet', 'DaemonSet'].includes(o.kind) ? o.kind + '/' + o.name : '';
}
// isCounter tells whether a sample only grows, so its rate is what matters.
function isCounter(type, name) {
  return type === 'counter' || (['histogram', 'summary'].includes(type) && /_(sum|count|bucket)$/.test(name)) ||
    (type === 'untyped' && /_total$/.test(name));
}

// watchDialog changes a watch w, or watches a metric of the page that pod
// (whose workload is owner, if any) exposes in namespace ns.
function watchDialog({ watch: w, ns, owner, pod, family, port, path }) {
  const field = (label, input, help) => h('label', { class: 'field' }, h('span', null, label), input,
    help ? h('span', { class: 'muted small-text' }, help) : null);
  if (w) ns = w.namespace;
  const targets = w ? [w.target] : [owner, 'Pod/' + pod].filter(Boolean);
  const target = h('select', { disabled: !!w }, targets.map(x => h('option', { value: x },
    x.startsWith('Pod/') ? t('onlyThisPod', x.slice(4)) : t('allPodsOf', x))));
  const name = h('input', { type: 'text', value: w ? w.name : '', maxlength: '100', autocomplete: 'off', spellcheck: 'false' });
  const metric = h('input', { type: 'text', class: 'mono', value: w ? w.metric : '', autocomplete: 'off', spellcheck: 'false' });
  const labels = h('input', { type: 'text', class: 'mono', value: w ? labelsInput(w.labels) : '', placeholder: 'code=500', autocomplete: 'off', spellcheck: 'false' });
  const rate = h('input', { type: 'checkbox', checked: !!(w && w.rate) });
  const aggregate = h('select', null, ['sum', 'avg', 'max', 'min'].map(a => h('option', { value: a, selected: (w ? w.aggregate : 'sum') === a }, t('agg.' + a))));
  const above = h('input', { type: 'number', step: 'any', value: w && w.above != null ? String(w.above) : '' });
  const below = h('input', { type: 'number', step: 'any', value: w && w.below != null ? String(w.below) : '' });
  const portIn = h('input', { type: 'text', inputmode: 'numeric', value: w ? w.port : port });
  const pathIn = h('input', { type: 'text', class: 'mono', value: w ? w.path : path, spellcheck: 'false' });
  // The family's series to choose from: all of each sample name, or one
  // set of labels. Choosing one fills in the fields below.
  let series = null;
  if (family) {
    // A histogram's count comes first: how many a second is what is
    // usually wanted; its buckets last.
    const rank = n => (/_count$/.test(n) ? 0 : /_sum$/.test(n) ? 1 : /_bucket$/.test(n) ? 3 : 2);
    const names = [...new Set(family.samples.map(s => s.name))].sort((a, b) => rank(a) - rank(b));
    const choices = names.map(n => ({ name: n, labels: {}, text: t('allSeries', n) }));
    for (const s of family.samples.slice(0, 50)) {
      if (Object.keys(s.labels || {}).length) choices.push({ name: s.name, labels: s.labels, text: s.name + labelsText(s.labels) });
    }
    let named = false;
    name.addEventListener('input', () => { named = true; });
    const pick = c => {
      metric.value = c.name;
      labels.value = labelsInput(c.labels);
      rate.checked = isCounter(family.type, c.name);
      if (!named) name.value = c.name;
    };
    series = h('select', { class: 'mono', onchange: () => pick(choices[Number(series.value)]) },
      choices.map((c, i) => h('option', { value: String(i) }, c.text)));
    pick(choices[0]);
  }
  const note = h('div', { class: 'form-status', role: 'status' });
  const say = (text, kind) => {
    note.className = kind ? 'form-status ' + kind : 'form-status';
    note.textContent = text;
  };
  const number = v => (v.trim() === '' ? null : Number(v));
  const buttons = [];
  const busy = on => buttons.forEach(b => { b.disabled = on; });
  const form = h('form', {
    class: 'dialog wide',
    onsubmit: async e => {
      e.preventDefault();
      const parsed = parseLabelsInput(labels.value);
      if (!parsed) {
        say(t('badLabels'), 'bad');
        return;
      }
      busy(true);
      try {
        await api(w ? watchPath(ns, w.id) : watchPath(ns), {
          method: w ? 'PUT' : 'POST',
          body: {
            name: name.value, target: target.value, port: portIn.value.trim(), path: pathIn.value.trim(), metric: metric.value.trim(),
            labels: parsed, rate: rate.checked, aggregate: aggregate.value, above: number(above.value), below: number(below.value),
          },
        });
        close();
        toast(t('watchSaved'));
        if (state.view === 'appmetrics') refresh();
      } catch (err) {
        if (err.status !== 401) say(err.message, 'bad');
        busy(false);
      }
    },
  },
  h('h2', null, w ? t('editWatch') : t('watchTitle')),
  series ? field(t('watchSeries'), series) : null,
  h('div', { class: 'field-row' }, field(t('watchMetric'), metric), field(t('watchLabels'), labels, t('watchLabelsHelp'))),
  h('label', { class: 'check-line' }, rate, t('watchRate')),
  h('div', { class: 'field-row' }, field(t('watchTarget'), target), field(t('watchAggregate'), aggregate)),
  h('div', { class: 'field-row' }, field(t('watchAbove'), above, t('watchLimitHelp')), field(t('watchBelow'), below)),
  h('div', { class: 'field-row' }, field(t('col.name'), name), h('div', { class: 'field-row' }, field(t('port'), portIn), field(t('path'), pathIn))),
  note,
  h('div', { class: 'dialog-actions' },
    h('span', { class: 'grow' }),
    buttons[0] = button(t('cancel'), () => close()),
    buttons[1] = h('button', { type: 'submit', class: 'btn primary' }, t('save'))));
  const close = modal(form);
  (series || metric).focus();
}

// ---------------------------------------------------------------- actions

function workloadPath(w, action) {
  return clusterPath() + '/namespaces/' + enc(w.namespace) + '/workloads/' + enc(w.kind.toLowerCase()) + '/' + enc(w.name) + '/' + action;
}

async function restartWorkload(w) {
  const ok = await ask({ title: t('restartTitle'), message: t('restartConfirm', w.kind + ' ' + w.namespace + '/' + w.name), confirm: t('restart'), danger: true });
  if (ok) runAction(workloadPath(w, 'restart'));
}

async function scaleWorkload(w) {
  const v = await ask({ title: t('scaleTitle'), message: w.kind + ' ' + w.namespace + '/' + w.name, input: String(w.desired), confirm: t('scale') });
  if (v == null) return;
  const n = Number(v);
  if (v.trim() === '' || !Number.isInteger(n) || n < 0) {
    toast(t('badReplicas'), true);
    return;
  }
  runAction(workloadPath(w, 'scale'), { body: { replicas: n } });
}

async function deletePod(p) {
  const ok = await ask({ title: t('deleteTitle'), message: t('deleteConfirm', p.namespace + '/' + p.name), confirm: t('deletePod'), danger: true });
  if (ok) runAction(clusterPath() + '/namespaces/' + enc(p.namespace) + '/pods/' + enc(p.name), { method: 'DELETE' });
}

async function cordonNode(n, cordon) {
  const ok = await ask({ title: t('cordonTitle'), message: t(cordon ? 'cordonConfirm' : 'uncordonConfirm', n.name), confirm: cordon ? t('cordon') : t('uncordon'), danger: cordon });
  if (ok) runAction(clusterPath() + '/nodes/' + enc(n.name) + '/cordon', { body: { unschedulable: cordon } });
}

async function triggerCronJob(c) {
  const ok = await ask({ title: t('runNowTitle'), message: t('runNowConfirm', c.namespace + '/' + c.name), confirm: t('runNow') });
  if (ok) runAction(clusterPath() + '/namespaces/' + enc(c.namespace) + '/cronjobs/' + enc(c.name) + '/trigger');
}

async function suspendCronJob(c, suspend) {
  const ok = await ask({ title: suspend ? t('suspend') : t('resume'), message: t(suspend ? 'suspendConfirm' : 'resumeConfirm', c.namespace + '/' + c.name), confirm: suspend ? t('suspend') : t('resume') });
  if (ok) runAction(clusterPath() + '/namespaces/' + enc(c.namespace) + '/cronjobs/' + enc(c.name) + '/suspend', { body: { suspend } });
}

async function runAction(path, { method = 'POST', body } = {}) {
  try {
    const res = await api(path, { method, body });
    toast(res.message || t('done'));
    refresh();
    if (state.obj) reloadDetail();
    return true;
  } catch (e) {
    if (e.status !== 401) toast(e.message, true);
    return false;
  }
}

function toast(message, error) {
  const el = h('div', { class: error ? 'toast error' : 'toast' }, message);
  toasts.append(el);
  setTimeout(() => el.remove(), error ? 8000 : 4000);
}

// ask shows a small dialog; it resolves to the input's value (or true) when
// confirmed and to null when cancelled.
function ask({ title, message, input, confirm, danger }) {
  return new Promise(resolve => {
    const field = input == null ? null : h('input', { type: 'number', min: '0', step: '1', value: input, 'aria-label': t('replicas') });
    const done = v => {
      overlay.remove();
      document.removeEventListener('keydown', onKey, true);
      resolve(v);
    };
    const onKey = e => {
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        done(null);
      }
    };
    const submit = h('button', { type: 'submit', class: danger ? 'btn primary danger-primary' : 'btn primary' }, confirm);
    const form = h('form', { class: 'dialog', onsubmit: e => { e.preventDefault(); done(field ? field.value : true); } },
      h('h2', null, title), h('p', null, message), field,
      h('div', { class: 'dialog-actions' }, button(t('cancel'), () => done(null)), submit));
    const overlay = h('div', { class: 'overlay', onclick: e => { if (e.target === overlay) done(null); } }, form);
    document.body.append(overlay);
    document.addEventListener('keydown', onKey, true);
    (field || submit).focus();
  });
}

// ---------------------------------------------------------------- detail panel

// An object in the panel is named by "group/version/resource/namespace/name"
// ("core" for the core group, "-" for no namespace), which is also its URL
// parameter.
function objParam(ref) {
  return [ref.gvr, ref.ns || '-', ref.name].join('/');
}
function parseObj(s) {
  const p = (s || '').split('/');
  if (p.length < 5) return null;
  return { gvr: p.slice(0, 3).join('/'), ns: p[3] === '-' ? '' : p[3], name: p.slice(4).join('/') };
}

// detail is the state of the panel. All of it belongs to one object; opening
// another starts over.
let detail = null;
function resetDetail() {
  if (detail) clearInterval(detail.followTimer);
  detail = {
    key: '', ref: null, kind: '', obj: null, text: '', error: null, stale: '', seq: 0,
    cache: {}, source: null, drawn: '', drawnAt: 0, logs: null, console: null, editing: null, hours: 1,
  };
}

async function openDetail(ref, tab) {
  if (objParam(ref) !== state.obj && !(await leaveEditor())) return;
  if (ref.kind) discoveredKinds.set(ref.gvr, ref.kind);
  go({ q: state.q, problems: state.problems, rest: state.rest, obj: objParam(ref), tab: tab || '' });
}
async function closeDetail() {
  if (!(await leaveEditor())) return;
  go({ q: state.q, problems: state.problems, rest: state.rest });
}
// leaveEditor asks before YAML edits that were not saved are thrown away.
async function leaveEditor() {
  const ed = detail.editing;
  if (!ed || ed.text === ed.original) return true;
  const ok = await ask({ title: t('discardTitle'), message: t('discardConfirm'), confirm: t('discard'), danger: true });
  if (ok) detail.editing = null;
  return !!ok;
}
function showTab(tab) {
  history.replaceState(null, '', currentHash({ tab }));
  state.tab = tab;
  renderDetail();
}

// Kinds of custom objects opened from the resource browser, by their gvr.
const discoveredKinds = new Map();

function kindOf(gvr) {
  return API_KIND[gvr] || discoveredKinds.get(gvr) || gvr.split('/')[2];
}

function tabsFor(kind) {
  const tabs = ['summary'];
  if (kind === 'Pod') tabs.push('logs');
  if (['Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'Node'].includes(kind)) tabs.push('pods');
  if (kind === 'CronJob') tabs.push('jobs');
  tabs.push('yaml', 'events');
  if (['Deployment', 'StatefulSet', 'DaemonSet', 'CronJob', 'Node'].includes(kind)) tabs.push('changes');
  if (kind === 'Deployment') tabs.push('history');
  const c = currentCluster();
  if ((kind === 'Pod' || kind === 'Node') && c && c.metricsAvailable) tabs.push('metrics');
  if (['Pod', 'Deployment', 'StatefulSet', 'DaemonSet'].includes(kind)) tabs.push('scrape');
  if (kind === 'Pod' && canIn('admin', detail.ref ? detail.ref.ns : '')) tabs.push('console');
  return tabs;
}
function currentTab() {
  const tabs = tabsFor(detail.kind);
  return tabs.includes(state.tab) ? state.tab : 'summary';
}

function objectPath(ref, query) {
  const [group, version, resource] = ref.gvr.split('/');
  const q = new URLSearchParams(Object.assign(ref.ns ? { namespace: ref.ns } : {}, query)).toString();
  return clusterPath() + '/resources/' + [group, version, resource, ref.name].map(enc).join('/') + (q ? '?' + q : '');
}

// loadDetailObject fetches the object. A quiet reload redraws only when the
// object changed, and keeps showing it when the reload fails.
async function loadDetailObject(quiet) {
  const d = detail;
  const my = ++d.seq;
  try {
    const text = await api(objectPath(d.ref), { text: true });
    if (detail !== d || d.seq !== my) return;
    const wasStale = d.stale;
    d.stale = '';
    if (text === d.text && !d.error) {
      if (wasStale) renderDetailHead();
      return;
    }
    d.text = text;
    d.obj = JSON.parse(text);
    d.error = null;
    if (d.obj.kind && !API_KIND[d.ref.gvr]) d.kind = d.obj.kind;
  } catch (e) {
    if (detail !== d || d.seq !== my || e.name === 'AbortError') return;
    if (quiet && d.obj) {
      d.stale = e.message;
      renderDetailHead();
      return;
    }
    d.error = e;
  }
  // The logs and the console keep what they show; only the header changes.
  if (quiet && ['logs', 'console', 'scrape'].includes(currentTab())) renderDetailHead();
  else renderDetail();
}

function reloadDetail() {
  if (!detail.ref) return;
  detail.cache = {};
  loadDetailObject();
}

// detailTick runs with every refresh of the lists: the open object and the
// data of its tab are reloaded quietly. Nothing happens while text in the
// panel is selected or its YAML is being edited.
function detailTick() {
  const d = detail;
  if (!d.ref || !d.obj || d.editing || document.hidden || selectionInside(els.detail)) return;
  loadDetailObject(true);
  const src = d.source;
  if (src) {
    const c = d.cache[src.name];
    if (c && !c.loading && Date.now() - c.at >= src.maxAge) fetchInto(src.name, src.load);
  }
  // Ages move on even when nothing else does.
  if (Date.now() - d.drawnAt > 60000 && !['logs', 'console', 'yaml', 'scrape'].includes(currentTab())) renderDetail();
}

// Tab data is kept per object. fetchInto keeps the last value while it
// reloads and redraws only when something changed.
function fetchInto(name, load) {
  const d = detail;
  const prev = d.cache[name];
  d.cache[name] = { value: prev && prev.value, loading: true, at: prev ? prev.at : 0 };
  load().then(value => {
    if (detail !== d) return;
    const old = prev && prev.value;
    const same = old !== undefined && (old === value ||
      ((!Array.isArray(value) || value.length <= 1000) && JSON.stringify(old) === JSON.stringify(value)));
    d.cache[name] = { value, at: Date.now() };
    if (!same) renderDetail();
  }, error => {
    if (detail !== d || error.name === 'AbortError') return;
    d.cache[name] = { value: prev && prev.value, error, at: Date.now() };
    renderDetail();
  });
}

// fromCache draws a tab from its data, loading it first when needed; maxAge
// is how old the data may get before detailTick reloads it.
function fromCache(name, load, draw, maxAge = 0) {
  detail.source = { name, load, maxAge };
  if (!detail.cache[name]) fetchInto(name, load);
  const c = detail.cache[name];
  if (c.value !== undefined) draw(c.value);
  else if (c.error) fill(els.detailBody, errorPanel(c.error));
  else fill(els.detailBody, h('div', { class: 'empty-note' }, t('loading')));
}

// The panel's width is dragged at its left edge and kept in this browser.
function startResize(e) {
  e.preventDefault();
  const move = ev => {
    const w = Math.max(420, Math.min(window.innerWidth - 60, window.innerWidth - ev.clientX));
    els.detail.style.width = w + 'px';
  };
  const up = () => {
    document.removeEventListener('mousemove', move);
    document.removeEventListener('mouseup', up);
    document.body.classList.remove('resizing');
    writeStore('localStorage', 'kartal.detailWidth', String(parseInt(els.detail.style.width, 10) || ''));
  };
  document.body.classList.add('resizing');
  document.addEventListener('mousemove', move);
  document.addEventListener('mouseup', up);
}

function renderDetail() {
  if (!els.detail) return;
  const ref = parseObj(state.obj);
  if (!ref) {
    if (detail.key) resetDetail();
    els.detail.hidden = true;
    return;
  }
  if (detail.key !== state.obj) {
    resetDetail();
    detail.key = state.obj;
    detail.ref = ref;
    detail.kind = kindOf(ref.gvr);
    loadDetailObject();
  }
  els.detail.hidden = false;
  const tabs = tabsFor(detail.kind);
  const tab = tabs.includes(state.tab) ? state.tab : 'summary';
  if (tab !== 'logs') stopFollow();
  // Drawing the same tab again keeps its scroll position.
  const scroll = detail.drawn === tab && els.detailBody ? els.detailBody.scrollTop : 0;
  detail.drawn = tab;
  detail.drawnAt = Date.now();
  detail.source = null;
  els.detailHead = h('div', { class: 'detail-head' });
  els.detailBody = h('div', { class: tab === 'logs' || tab === 'console' ? 'detail-body fill' : 'detail-body' });
  fill(els.detail, els.detailResize, els.detailHead,
    h('nav', { class: 'detail-tabs', role: 'tablist' }, tabs.map(id => h('button', {
      type: 'button', role: 'tab', class: id === tab ? 'dtab active' : 'dtab', 'aria-selected': String(id === tab),
      onclick: () => showTab(id),
    }, t('tab.' + id)))),
    els.detailBody);
  renderDetailHead();
  if (detail.error) fill(els.detailBody, errorPanel(detail.error));
  else if (!detail.obj) fill(els.detailBody, h('div', { class: 'empty-note' }, t('loading')));
  else DETAIL_TABS[tab]();
  els.detailBody.scrollTop = scroll;
}

const DETAIL_TABS = {
  summary: renderSummary, yaml: renderYAMLTab, events: renderEventsTab, pods: renderPodsTab, jobs: renderJobsTab,
  changes: renderChangesTab, history: renderHistoryTab, metrics: renderMetricsTab, logs: renderLogsTab, console: renderConsoleTab,
  scrape: renderScrapeTab,
};

function objectStatus(kind, o) {
  const st = o.status || {};
  if (o.metadata && o.metadata.deletionTimestamp) return pill('Terminating', 'warn');
  switch (kind) {
    case 'Pod': {
      const waiting = (st.containerStatuses || []).map(c => c.state && c.state.waiting && c.state.waiting.reason).find(Boolean);
      const ready = (st.containerStatuses || []).every(c => c.ready);
      const text = waiting || st.reason || st.phase || '—';
      return pill(text, st.phase === 'Succeeded' || (st.phase === 'Running' && ready && !waiting) ? 'ok' : 'bad');
    }
    case 'Deployment': case 'StatefulSet': {
      const want = o.spec && o.spec.replicas != null ? o.spec.replicas : 1;
      const ready = st.readyReplicas || 0;
      return pill(ready + '/' + want + ' ' + t('ready'), ready < want ? 'bad' : 'ok');
    }
    case 'DaemonSet':
      return pill((st.numberReady || 0) + '/' + (st.desiredNumberScheduled || 0) + ' ' + t('ready'),
        (st.numberReady || 0) < (st.desiredNumberScheduled || 0) ? 'bad' : 'ok');
    case 'Node': {
      const ready = (st.conditions || []).find(c => c.type === 'Ready');
      const ok = ready && ready.status === 'True';
      const cordoned = !!(o.spec && o.spec.unschedulable);
      return pill((ok ? 'Ready' : 'NotReady') + (cordoned ? ', SchedulingDisabled' : ''), ok ? (cordoned ? 'warn' : 'ok') : 'bad');
    }
    case 'Job': {
      const done = (st.conditions || []).find(c => (c.type === 'Complete' || c.type === 'Failed') && c.status === 'True');
      if (done) return pill(done.type, done.type === 'Complete' ? 'ok' : 'bad');
      return st.active ? pill('Running', 'ok') : null;
    }
    case 'PersistentVolumeClaim':
      return pill(st.phase || '—', st.phase === 'Bound' ? 'ok' : 'warn');
    case 'CronJob':
      return o.spec && o.spec.suspend ? pill(t('f.suspend'), 'warn') : null;
    default:
      return st.phase ? pill(st.phase, 'ok') : null;
  }
}

function renderDetailHead() {
  if (!els.detailHead) return;
  const { ref, kind, obj } = detail;
  const fkey = KIND_VIEW[kind] ? kind + '/' + (ref.ns || '') + '/' + ref.name : null;
  const actions = [];
  if (obj && !(obj.metadata && obj.metadata.deletionTimestamp)) {
    const w = { kind, namespace: ref.ns, name: ref.name, desired: obj.spec && obj.spec.replicas != null ? obj.spec.replicas : 1 };
    if (kind === 'Pod') actions.push(actionButton(t('deletePod'), () => deletePod({ namespace: ref.ns, name: ref.name }), { cls: 'danger', where: ref.ns }));
    if (kind === 'Deployment' || kind === 'StatefulSet') actions.push(actionButton(t('scale'), () => scaleWorkload(w), { where: ref.ns }));
    if (WORKLOAD_KINDS.has(kind)) actions.push(actionButton(t('restart'), () => restartWorkload(w), { cls: 'danger', where: ref.ns }));
    if (kind === 'CronJob') {
      const c = { namespace: ref.ns, name: ref.name, suspended: !!(obj.spec && obj.spec.suspend) };
      actions.push(actionButton(t('runNow'), () => triggerCronJob(c), { where: ref.ns }),
        actionButton(c.suspended ? t('resume') : t('suspend'), () => suspendCronJob(c, !c.suspended), { where: ref.ns }));
    }
    if (kind === 'Node') {
      const cordoned = !!(obj.spec && obj.spec.unschedulable);
      actions.push(actionButton(cordoned ? t('uncordon') : t('cordon'), () => cordonNode({ name: ref.name }, !cordoned), { where: '' }));
    }
  }
  fill(els.detailHead,
    h('div', { class: 'detail-title' },
      fkey ? starButton(favs.obj.includes(fkey), () => toggleFav('obj', fkey)) : null,
      h('span', { class: 'kind-badge' }, kind),
      h('span', { class: 'detail-name', title: ref.name }, ref.name),
      h('button', { type: 'button', class: 'icon-btn small', title: t('copy'), onclick: () => copyText(ref.name) }, '⧉'),
      ref.ns ? h('span', { class: 'chip small-chip', title: t('namespace') }, ref.ns) : null,
      obj ? objectStatus(kind, obj) : null,
      detail.stale ? h('span', { class: 'stale-note', title: detail.stale }, '⚠ ' + t('gone', detail.stale)) : null),
    h('div', { class: 'detail-actions' }, actions,
      h('button', { type: 'button', class: 'icon-btn', title: t('refresh'), onclick: reloadDetail }, '↻'),
      h('button', { type: 'button', class: 'icon-btn', title: t('close') + ' (Esc)', onclick: closeDetail }, '✕')));
}

// ---------------------------------------------------------------- detail: summary

function facts(pairs) {
  const rows = pairs.filter(([, v]) => v != null && v !== '' && !(Array.isArray(v) && !v.length));
  return rows.length ? h('dl', { class: 'facts' }, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)])) : null;
}
function chips(map) {
  const entries = Object.entries(map || {});
  if (!entries.length) return h('span', { class: 'muted' }, t('none'));
  return h('div', { class: 'chips' }, entries.map(([k, v]) => h('span', { class: 'label-chip', title: k + '=' + v }, k, v ? h('span', { class: 'muted' }, '=' + v) : null)));
}
function kvList(map) {
  const entries = Object.entries(map || {});
  if (!entries.length) return null;
  return h('div', { class: 'kv' }, entries.map(([k, v]) => {
    const long = String(v).length > 160;
    const val = h('span', { class: 'mono kv-value' }, long ? String(v).slice(0, 160) + '…' : String(v));
    return h('div', { class: 'kv-row' }, h('span', { class: 'kv-key mono' }, k),
      val, long ? button(t('f.showAll'), e => { val.textContent = String(v); e.target.remove(); }, 'small') : null);
  }));
}
function section(title, body) {
  return body == null ? null : h('section', { class: 'dsection' }, h('h3', null, title), body);
}
function conditionsTable(conds) {
  if (!conds || !conds.length) return null;
  return h('table', { class: 'compact' },
    h('thead', null, h('tr', null, ['type', 'status', 'reason', 'message', 'lastSeen'].map(k => h('th', null, t('col.' + k))))),
    h('tbody', null, conds.map(c => h('tr', null,
      h('td', null, c.type),
      h('td', null, pill(c.status, c.status === 'True' ? (/Pressure|Unavailable|Failed/.test(c.type) ? 'bad' : 'ok') : (/Pressure|Unavailable|Failed/.test(c.type) ? 'ok' : 'warn'))),
      h('td', null, c.reason || ''),
      h('td', null, c.message || ''),
      h('td', null, age(c.lastTransitionTime || c.lastUpdateTime || c.lastProbeTime))))));
}
function resourcesText(res) {
  if (!res) return '—';
  const r = res.requests || {};
  const l = res.limits || {};
  const part = (label, m) => (m.cpu || m.memory ? label + ' ' + [m.cpu && 'cpu ' + m.cpu, m.memory && 'mem ' + m.memory].filter(Boolean).join(', ') : null);
  return [part(t('request'), r), part(t('limit'), l)].filter(Boolean).join(' · ') || '—';
}
function containerState(s) {
  if (!s) return '—';
  if (s.running) return pill(t('running') + ' · ' + ago(s.running.startedAt), 'ok');
  if (s.waiting) return pill(s.waiting.reason || t('waiting'), 'bad');
  if (s.terminated) return pill((s.terminated.reason || t('terminated')) + ' (' + s.terminated.exitCode + ')', s.terminated.exitCode ? 'bad' : 'ok');
  return '—';
}
function containersTable(containers, statuses) {
  if (!containers || !containers.length) return null;
  const byName = Object.fromEntries((statuses || []).map(s => [s.name, s]));
  const withStatus = statuses != null;
  return h('table', { class: 'compact' },
    h('thead', null, h('tr', null, ['name', 'image', 'ports', 'resources'].concat(withStatus ? ['state', 'ready', 'restarts', 'lastTermination'] : []).map(k => h('th', null, t('col.' + k))))),
    h('tbody', null, containers.map(c => {
      const s = byName[c.name] || {};
      const last = s.lastState && s.lastState.terminated;
      return h('tr', { class: withStatus && s.ready === false ? 'problem' : null },
        h('td', null, h('strong', null, c.name)),
        h('td', null, mono(c.image)),
        h('td', null, mono((c.ports || []).map(p => p.containerPort + '/' + (p.protocol || 'TCP') + (p.name ? ' (' + p.name + ')' : '')).join(', ') || '—')),
        h('td', null, h('span', { class: 'small-text' }, resourcesText(c.resources))),
        withStatus ? [
          h('td', null, containerState(s.state)),
          h('td', null, s.ready ? '✓' : '✗'),
          h('td', null, s.restartCount ? pill(s.restartCount, 'warn') : '0'),
          h('td', null, last ? h('span', { class: last.reason === 'OOMKilled' || last.exitCode ? 'status-bad' : null },
            (last.reason || '') + ' (' + last.exitCode + ') · ' + ago(last.finishedAt)) : '—'),
        ] : null);
    })));
}
// ownerLinks links an object to what controls it. A Deployment's pods belong
// to one of its ReplicaSets, named after it plus the pod template's hash:
// the link goes to the Deployment, which is what people look for.
function ownerLinks(md, ns) {
  const owners = md.ownerReferences || [];
  if (!owners.length) return null;
  const hash = md.labels && md.labels['pod-template-hash'];
  return owners.map(o => {
    let { kind, name } = o;
    if (kind === 'ReplicaSet' && hash && name.endsWith('-' + hash)) {
      kind = 'Deployment';
      name = name.slice(0, -hash.length - 1);
    }
    const gvr = KIND_API[kind];
    return gvr
      ? h('button', { type: 'button', class: 'link-button', title: o.kind + '/' + o.name, onclick: () => openDetail({ gvr, ns, name }) }, kind + '/' + name)
      : o.kind + '/' + o.name;
  });
}
function nodeLink(name) {
  return name ? h('button', { type: 'button', class: 'link-button', onclick: () => openDetail({ gvr: KIND_API.Node, ns: '', name }) }, name) : '—';
}

function renderSummary() {
  const o = detail.obj;
  const kind = detail.kind;
  const md = o.metadata || {};
  const spec = o.spec || {};
  const st = o.status || {};
  const common = [
    [t('f.created'), age(md.creationTimestamp)],
    [t('f.owner'), ownerLinks(md, detail.ref.ns)],
  ];
  let specific = [];
  let extra = [];
  switch (kind) {
    case 'Pod':
      specific = [
        [t('f.node'), nodeLink(spec.nodeName)], [t('f.podIP'), mono(st.podIP || '—')], [t('f.qos'), st.qosClass],
        [t('f.serviceAccount'), spec.serviceAccountName], [t('f.restartPolicy'), spec.restartPolicy],
        [t('f.priority'), spec.priorityClassName], [t('f.started'), age(st.startTime)],
      ];
      extra = [
        section(t('f.containers'), containersTable(spec.containers, st.containerStatuses || [])),
        section(t('f.initContainers'), containersTable(spec.initContainers, st.initContainerStatuses || [])),
        section(t('f.conditions'), conditionsTable(st.conditions)),
      ];
      break;
    case 'Deployment': case 'StatefulSet': case 'DaemonSet': {
      const tpl = (spec.template && spec.template.spec) || {};
      specific = [
        [t('f.replicas'), kind === 'DaemonSet'
          ? (st.numberReady || 0) + '/' + (st.desiredNumberScheduled || 0) + ' ' + t('ready')
          : (st.readyReplicas || 0) + '/' + (spec.replicas != null ? spec.replicas : 1) + ' ' + t('ready') + ' · ' + (st.updatedReplicas || 0) + ' ' + t('col.updated').toLowerCase()],
        [t('f.strategy'), (spec.strategy && spec.strategy.type) || (spec.updateStrategy && spec.updateStrategy.type)],
        [t('f.revision'), md.annotations && md.annotations['deployment.kubernetes.io/revision']],
        [t('f.selector'), spec.selector && spec.selector.matchLabels ? chips(spec.selector.matchLabels) : null],
      ];
      extra = [section(t('f.containers'), containersTable(tpl.containers)), section(t('f.conditions'), conditionsTable(st.conditions))];
      break;
    }
    case 'Node': {
      const info = st.nodeInfo || {};
      const snap = snapshotNode(detail.ref.name);
      specific = [
        [t('f.addresses'), (st.addresses || []).map(a => a.type + ': ' + a.address).join(' · ')],
        [t('f.os'), info.osImage], [t('f.kernel'), info.kernelVersion], [t('f.runtime'), info.containerRuntimeVersion],
        [t('f.kubelet'), info.kubeletVersion], [t('f.unschedulable'), spec.unschedulable ? t('yes') : t('no')],
      ];
      // Requests, limits and usage are summed over the node's pods, and
      // shown against what the node can hand out.
      const share = (v, total, f) => (v == null ? '—' : f(v) + (total ? ' (' + pct(v, total) + '%)' : ''));
      const of = (field, key, f) => (snap && snap[field] ? share(snap[field][key], snap.allocatable[key], f) : '—');
      const row = (r, cells) => h('tr', null, h('td', null, r), h('td', null, (st.capacity || {})[r] || '—'),
        h('td', null, (st.allocatable || {})[r] || '—'), cells.map(c => h('td', null, c)));
      extra = [
        section(t('f.capacity'), h('table', { class: 'compact' },
          h('thead', null, h('tr', null, ['resource', 'capacity', 'allocatable', 'requests', 'limits', 'usage'].map(k => h('th', null, t('col.' + k))))),
          h('tbody', null,
            row('cpu', [of('requests', 'cpuMilli', cpu), of('limits', 'cpuMilli', cpu), of('usage', 'cpuMilli', cpu)]),
            row('memory', [of('requests', 'memoryBytes', bytes), of('limits', 'memoryBytes', bytes), of('usage', 'memoryBytes', bytes)]),
            row('pods', [snap ? share(snap.podCount, snap.allocatable.pods, String) : '—', '—', '—'])))),
        section(t('f.taints'), (spec.taints || []).length ? h('table', { class: 'compact' },
          h('thead', null, h('tr', null, ['key', 'value', 'effect'].map(k => h('th', null, t('col.' + k))))),
          h('tbody', null, spec.taints.map(x => h('tr', null, h('td', null, mono(x.key)), h('td', null, x.value || ''), h('td', null, x.effect))))) : null),
        section(t('f.conditions'), conditionsTable(st.conditions)),
      ];
      break;
    }
    case 'Service':
      specific = [
        [t('f.type'), spec.type], [t('f.clusterIP'), mono((spec.clusterIPs || [spec.clusterIP]).filter(Boolean).join(', '))],
        [t('f.externalIPs'), (spec.externalIPs || []).join(', ')], [t('f.sessionAffinity'), spec.sessionAffinity],
        [t('f.selector'), spec.selector ? chips(spec.selector) : null],
      ];
      extra = [section(t('f.ports'), (spec.ports || []).length ? h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['name', 'port', 'target', 'nodePort', 'protocol'].map(k => h('th', null, t('col.' + k))))),
        h('tbody', null, spec.ports.map(p => h('tr', null, h('td', null, p.name || '—'), h('td', null, p.port), h('td', null, String(p.targetPort != null ? p.targetPort : '—')),
          h('td', null, p.nodePort || '—'), h('td', null, p.protocol || 'TCP'))))) : null)];
      break;
    case 'Ingress':
      specific = [[t('f.class'), spec.ingressClassName], [t('f.tls'), (spec.tls || []).flatMap(x => x.hosts || []).join(', ')]];
      extra = [section(t('f.rules'), h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['host', 'path', 'backend'].map(k => h('th', null, t('col.' + k))))),
        h('tbody', null, (spec.rules || []).flatMap(r => ((r.http && r.http.paths) || [{}]).map(p => h('tr', null,
          h('td', null, hostLink(r.host, p.path, (spec.tls || []).length > 0)), h('td', null, mono((p.path || '/') + (p.pathType ? ' (' + p.pathType + ')' : ''))),
          h('td', null, p.backend && p.backend.service ? p.backend.service.name + ':' + (p.backend.service.port.number || p.backend.service.port.name) : '—')))))))];
      break;
    case 'ConfigMap': {
      const keys = Object.entries(o.data || {}).map(([k, v]) => [k, new Blob([v]).size]).concat(Object.entries(o.binaryData || {}).map(([k, v]) => [k, Math.floor(v.length * 3 / 4)]));
      extra = [section(t('f.data'), keys.length ? h('table', { class: 'compact' },
        h('thead', null, h('tr', null, ['key', 'size'].map(k => h('th', null, t('col.' + k))))),
        h('tbody', null, keys.map(([k, n]) => h('tr', null, h('td', null, mono(k)), h('td', null, bytes(n)))))) : h('span', { class: 'muted' }, t('none')))];
      break;
    }
    case 'Secret':
      specific = [[t('f.type'), o.type], [t('f.keys'), Object.keys(o.data || {}).map(k => h('span', { class: 'label-chip' }, k, h('span', { class: 'muted' }, ' = ••• (' + t('hidden') + ')')))]];
      break;
    case 'PersistentVolumeClaim':
      specific = [
        [t('f.phase'), st.phase], [t('f.storage'), st.capacity && st.capacity.storage],
        [t('col.used'), claimUse(detail.ref.ns, detail.ref.name)],
        [t('f.requestedStorage'), spec.resources && spec.resources.requests && spec.resources.requests.storage],
        [t('col.storageClass'), spec.storageClassName], [t('f.accessModes'), (spec.accessModes || []).join(', ')],
        [t('f.volume'), mono(spec.volumeName || '—')], [t('f.volumeMode'), spec.volumeMode],
      ];
      extra = [section(t('f.conditions'), conditionsTable(st.conditions))];
      break;
    case 'Job':
      specific = [
        [t('f.completions'), (st.succeeded || 0) + '/' + (spec.completions != null ? spec.completions : 1)],
        [t('f.parallelism'), spec.parallelism], [t('f.backoffLimit'), spec.backoffLimit],
        [t('f.failed'), st.failed || 0], [t('f.active'), st.active || 0],
        [t('f.started'), age(st.startTime)], [t('f.completed'), st.completionTime ? age(st.completionTime) : null],
        [t('f.duration'), st.startTime ? duration(st.startTime, st.completionTime) : null],
      ];
      extra = [section(t('f.containers'), containersTable(spec.template && spec.template.spec && spec.template.spec.containers)), section(t('f.conditions'), conditionsTable(st.conditions))];
      break;
    case 'CronJob':
      specific = [
        [t('f.schedule'), mono(spec.schedule)], [t('f.timeZone'), spec.timeZone], [t('f.suspend'), spec.suspend ? t('yes') : t('no')],
        [t('f.concurrency'), spec.concurrencyPolicy], [t('f.lastSchedule'), age(st.lastScheduleTime)], [t('f.lastSuccess'), age(st.lastSuccessfulTime)],
      ];
      break;
    case 'Namespace':
      specific = [[t('f.status'), st.phase]];
      break;
    default:
      extra = [h('p', { class: 'muted' }, t('f.seeYaml'))];
  }
  fill(els.detailBody,
    facts(specific.concat(common)),
    section(t('f.labels'), chips(md.labels)),
    extra,
    driftSection(o),
    section(t('f.annotations'), kvList(md.annotations)));
}

// ---------------------------------------------------------------- detail: drift

const LAST_APPLIED = 'kubectl.kubernetes.io/last-applied-configuration';

// blank is a value the API server leaves out, so a missing one equals it.
function blank(v) {
  if (v == null || v === false || v === 0 || v === '') return true;
  if (Array.isArray(v)) return !v.length;
  return typeof v === 'object' && !Object.keys(v).length;
}

// itemKey is the field that names the items of two lists, if one does in
// both: containers and env by name, mounts by path, ports by number.
function itemKey(a, b) {
  return ['name', 'mountPath', 'containerPort', 'port', 'key'].find(k => [a, b].every(list => {
    const seen = new Set();
    return list.every(x => {
      if (!x || typeof x !== 'object' || x[k] == null || seen.has(x[k])) return false;
      seen.add(x[k]);
      return true;
    });
  }));
}

// sameScalar compares two values, quantities by their amount: kubectl may
// say 0.5 where the API server keeps 500m.
function sameScalar(path, a, b) {
  if (String(a) === String(b)) return true;
  if (!/\.(requests|limits|capacity|hard)\.|\.storage$/.test(path)) return false;
  const x = quantity(a, true);
  return x != null && x === quantity(b, true);
}

// driftOf lists [path, applied, now] for the fields the last kubectl apply
// set and that differ now. Only those fields are compared: the rest belongs
// to the API server and the controllers. An env var added since is listed
// too, as the next apply removes it.
function driftOf(applied, live, path = '', out = []) {
  if (applied === null || (blank(applied) && blank(live))) return out;
  if (Array.isArray(applied)) {
    const key = Array.isArray(live) && itemKey(applied, live);
    if (key) {
      const now = new Map(live.map(x => [x[key], x]));
      for (const a of applied) driftOf(a, now.get(a[key]), path + '[' + a[key] + ']', out);
      if (/\.env$/.test(path)) {
        for (const l of live) if (!applied.some(a => a[key] === l[key])) out.push([path + '[' + l[key] + ']', undefined, l]);
      }
    } else if (Array.isArray(live) && live.length === applied.length) {
      applied.forEach((a, i) => driftOf(a, live[i], path + '[' + i + ']', out));
    } else {
      out.push([path, applied, live]);
    }
  } else if (typeof applied === 'object') {
    if (live && typeof live === 'object' && !Array.isArray(live)) {
      for (const [k, v] of Object.entries(applied)) driftOf(v, live[k], path ? path + '.' + k : k, out);
    } else {
      out.push([path, applied, live]);
    }
  } else if (!sameScalar(path, applied, live)) {
    out.push([path, applied, live]);
  }
  return out;
}

// driftSection shows what changed in an object since it was last applied
// with kubectl (kubectl edit, scale, another tool): the next apply sets it
// back.
function driftSection(o) {
  const text = o.metadata && o.metadata.annotations && o.metadata.annotations[LAST_APPLIED];
  if (!text) return null;
  let applied;
  try {
    applied = JSON.parse(text);
  } catch {
    return null;
  }
  const found = driftOf(applied, o);
  if (!found.length) return section(t('drift'), h('div', { class: 'ok-note flush' }, '✓ ' + t('driftNone')));
  const show = v => {
    if (v === undefined) return h('span', { class: 'muted' }, '—');
    const s = typeof v === 'object' ? JSON.stringify(v) : String(v);
    return h('span', { class: 'mono', title: s.length > 200 ? s : null }, s.length > 200 ? s.slice(0, 200) + '…' : s);
  };
  return section(t('drift') + ' (' + found.length + ')', [
    h('p', { class: 'muted' }, t('driftHint')),
    h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['field', 'applied', 'now'].map(k => h('th', null, t('col.' + k))))),
      h('tbody', null, found.slice(0, 50).map(([path, a, l]) => h('tr', { class: 'problem' },
        h('td', null, mono(path)), h('td', null, show(a)), h('td', null, show(l)))))),
  ]);
}

// ---------------------------------------------------------------- detail: YAML

function yamlView(text) {
  const pre = h('pre', { class: 'yaml' });
  const frag = document.createDocumentFragment();
  for (const line of text.split('\n')) {
    const m = line.match(/^(\s*(?:- )?)([^\s"'#][^:]*?|"[^"]*"):(\s|$)(.*)$/);
    const row = document.createElement('div');
    if (m) {
      row.append(m[1]);
      const k = document.createElement('span');
      k.className = 'y-key';
      k.textContent = m[2] + ':';
      row.append(k, m[3] + m[4]);
    } else {
      row.textContent = line || ' ';
    }
    frag.append(row);
  }
  pre.append(frag);
  return pre;
}

// editableYAML is what the editor starts from: the object without its
// status, which the API server ignores on an update anyway.
function editableYAML(obj) {
  const copy = JSON.parse(JSON.stringify(obj));
  delete copy.status;
  return toYAML(copy);
}

function renderYAMLTab() {
  if (detail.editing) {
    renderYAMLEditor();
    return;
  }
  const o = detail.obj;
  const text = toYAML(o);
  const kind = detail.kind;
  const file = (kind || 'object').toLowerCase() + '-' + detail.ref.name + '.yaml';
  fill(els.detailBody,
    h('div', { class: 'detail-toolbar' },
      button(t('copy'), () => copyText(text)),
      button(t('download'), () => download(text, file)),
      kind === 'Secret' ? h('span', { class: 'muted' }, t('secretNoEdit')) : actionButton(t('edit'), () => {
        const text = editableYAML(o);
        detail.editing = { text, original: text, previewed: false, preview: null, busy: false, error: null };
        renderDetail();
      }, { role: 'admin', cap: 'edit', where: detail.ref.ns })),
    yamlView(text));
}

// renderYAMLEditor edits the object as YAML. Saving needs a preview of the
// same text first: the API server's dry run shows what would really be
// stored, defaults and all, as a diff.
function renderYAMLEditor() {
  const ed = detail.editing;
  const out = h('div');
  const save = h('button', { type: 'button', class: 'btn primary', onclick: () => send(false) }, t('save'));
  const gate = () => {
    save.disabled = !ed.previewed || ed.busy;
    save.title = ed.previewed ? '' : t('previewFirst');
  };
  const area = h('textarea', {
    class: 'yaml-edit', spellcheck: 'false', autocomplete: 'off', value: ed.text, 'aria-label': 'YAML',
    oninput: e => {
      ed.text = e.target.value;
      ed.previewed = false;
      ed.error = null;
      out.replaceChildren();
      gate();
    },
    onkeydown: e => {
      // Tab indents instead of leaving the editor.
      if (e.key === 'Tab' && !e.shiftKey && !e.ctrlKey && !e.altKey && !e.metaKey) {
        e.preventDefault();
        e.target.setRangeText('  ', e.target.selectionStart, e.target.selectionEnd, 'end');
        e.target.dispatchEvent(new Event('input'));
      }
    },
  });
  const send = async dryRun => {
    const d = detail;
    ed.busy = true;
    ed.error = null;
    gate();
    try {
      const res = await api(objectPath(d.ref, dryRun ? { dryRun: 'true' } : {}), { method: 'PUT', raw: ed.text, text: true });
      const next = JSON.parse(res);
      if (dryRun) {
        ed.previewed = true;
        ed.preview = diffLines(editableYAML(d.obj), editableYAML(next));
      } else {
        toast(t('saved'));
        d.editing = null;
        d.obj = next;
        d.text = res;
        refresh();
      }
    } catch (e) {
      if (e.status !== 401) ed.error = e.message;
    }
    ed.busy = false;
    if (detail === d) renderDetail();
  };
  fill(out,
    ed.error ? h('div', { class: 'banner error-banner' }, ed.error) : null,
    ed.previewed ? diffView(ed.preview) : null);
  gate();
  fill(els.detailBody,
    h('p', { class: 'muted' }, t('editHint')),
    h('div', { class: 'detail-toolbar' },
      button(t('preview'), () => send(true)), save,
      button(t('cancel'), async () => {
        if (await leaveEditor()) {
          detail.editing = null;
          renderDetail();
        }
      })),
    area, out);
}

// diffView shows a diff with long unchanged stretches folded away.
function diffView(lines) {
  if (lines == null) return h('div', { class: 'banner' }, t('diffTooBig'));
  if (!lines.some(l => l.t !== ' ')) return h('div', { class: 'ok-note' }, t('noChanges'));
  const CONTEXT = 3;
  const keep = lines.map(() => false);
  lines.forEach((l, i) => {
    if (l.t === ' ') return;
    for (let j = Math.max(0, i - CONTEXT); j <= Math.min(lines.length - 1, i + CONTEXT); j++) keep[j] = true;
  });
  const out = h('div', { class: 'diff' });
  let skipped = 0;
  const flush = () => {
    if (skipped) out.append(h('div', { class: 'diff-fold' }, '⋯ ' + t('unchanged', skipped)));
    skipped = 0;
  };
  lines.forEach((l, i) => {
    if (!keep[i]) {
      skipped++;
      return;
    }
    flush();
    out.append(h('div', { class: l.t === '+' ? 'diff-add' : l.t === '-' ? 'diff-del' : 'diff-same' }, (l.t === ' ' ? '  ' : l.t + ' ') + l.s));
  });
  flush();
  return out;
}

// ---------------------------------------------------------------- detail: events, pods, jobs, history

function renderEventsTab() {
  const { ref, kind } = detail;
  fromCache('events', () => api(clusterPath() + '/object-events?' + new URLSearchParams({ kind, namespace: ref.ns, name: ref.name })), events => {
    fill(els.detailBody, events.length ? h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['lastSeen', 'type', 'reason', 'message', 'count', 'firstSeen', 'source'].map(k => h('th', null, t('col.' + k))))),
      h('tbody', null, events.map(e => h('tr', { class: e.type === 'Warning' ? 'problem' : null },
        h('td', null, age(e.lastSeen)), h('td', null, pill(e.type, e.type === 'Warning' ? 'warn' : 'ok')),
        h('td', null, e.reason), h('td', null, e.message), h('td', null, e.count),
        h('td', null, age(e.firstSeen)), h('td', null, h('span', { class: 'muted' }, e.source || '')))))) : emptyState(t('noItems')));
  });
}

function renderPodsTab() {
  const { ref, kind } = detail;
  const path = clusterPath() + '/pods' + (ref.ns ? '?namespace=' + enc(ref.ns) : '');
  fromCache('pods', () => api(path), pods => {
    const mine = pods.filter(p => (kind === 'Node' ? p.node === ref.name : p.owner === kind + '/' + ref.name));
    fill(els.detailBody, renderTable('pods', mine, { filtered: false }));
  });
}

function renderJobsTab() {
  const { ref } = detail;
  fromCache('jobs', () => api(clusterPath() + '/jobs?namespace=' + enc(ref.ns)), jobs => {
    fill(els.detailBody, renderTable('jobs', jobs.filter(j => j.owner === 'CronJob/' + ref.name), { filtered: false }));
  });
}

function renderChangesTab() {
  const { ref, kind } = detail;
  const q = new URLSearchParams({ cluster: state.cluster, kind, name: ref.name });
  if (ref.ns) q.set('namespace', ref.ns);
  fromCache('changes', () => api('changes?' + q), items => {
    fill(els.detailBody, items.length ? changesTable(items, { object: false }) : emptyState(t('noChanges2')));
  }, 30000);
}

// The history asks the agent each time; it is reloaded on demand only.
function renderHistoryTab() {
  const { ref } = detail;
  const base = clusterPath() + '/namespaces/' + enc(ref.ns) + '/deployments/' + enc(ref.name);
  fromCache('history', () => api(base + '/history'), hist => {
    fill(els.detailBody, h('table', { class: 'compact' },
      h('thead', null, h('tr', null, ['revision', 'images', 'changeCause', 'replicas', 'age'].map(k => h('th', null, t('col.' + k))), h('th'))),
      h('tbody', null, hist.revisions.map(r => h('tr', { class: r.revision === hist.current ? 'current-row' : null },
        h('td', null, h('strong', null, '#' + r.revision), ' ', r.revision === hist.current ? h('span', { class: 'badge' }, t('current')) : null),
        h('td', null, mono(r.images.join(', '))),
        h('td', null, r.changeCause || h('span', { class: 'muted' }, '—')),
        h('td', null, r.ready + '/' + r.replicas),
        h('td', null, age(r.createdAt)),
        h('td', { class: 'actions-cell' }, r.revision === hist.current ? null : actionButton(t('rollbackTo'), async () => {
          const ok = await ask({
            title: t('rollbackTitle'), message: t('rollbackConfirm', 'Deployment ' + ref.ns + '/' + ref.name, r.revision),
            confirm: t('rollbackTo'), danger: true,
          });
          if (ok) runAction(base + '/rollback', { body: { revision: r.revision } });
        }, { where: ref.ns })))))));
  }, Infinity);
}

// ---------------------------------------------------------------- detail: metrics

// snapshotNode is the node as the agent reports it, with requests, limits
// and usage summed over its pods.
// claimUse shows how full a claim is, as the agent last reported.
function claimUse(ns, name) {
  if (!detail.cache.claims) fetchInto('claims', () => api(clusterPath() + '/volumeclaims?namespace=' + enc(ns)));
  const list = detail.cache.claims.value;
  const v = list && list.find(x => x.name === name);
  return v ? volumeUse(v) : null;
}

function snapshotNode(name) {
  if (!detail.cache.nodes) fetchInto('nodes', () => api(clusterPath() + '/nodes'));
  const list = detail.cache.nodes.value;
  return list ? list.find(n => n.name === name) : null;
}

function renderMetricsTab() {
  const { ref, kind } = detail;
  const hours = detail.hours;
  const q = new URLSearchParams({ kind: kind === 'Node' ? 'node' : 'pod', namespace: ref.ns, name: ref.name, hours: String(hours) });
  const guides = { cpu: [], memory: [] };
  if (kind === 'Node') {
    const n = snapshotNode(ref.name);
    if (n) {
      guides.cpu.push({ label: upper(t('allocatable')), value: n.allocatable.cpuMilli }, { label: upper(t('requested')), value: n.requests && n.requests.cpuMilli });
      guides.memory.push({ label: upper(t('allocatable')), value: n.allocatable.memoryBytes }, { label: upper(t('requested')), value: n.requests && n.requests.memoryBytes });
    }
  } else {
    const res = podResourcesOf(detail.obj);
    guides.cpu.push({ label: upper(t('request')), value: res.reqCPU }, { label: upper(t('limit')), value: res.limCPU });
    guides.memory.push({ label: upper(t('request')), value: res.reqMem }, { label: upper(t('limit')), value: res.limMem });
  }
  // A point is added once a minute, so the charts reload once a minute.
  fromCache('metrics' + hours, () => api(clusterPath() + '/metrics?' + q), m => {
    fill(els.detailBody,
      h('div', { class: 'detail-toolbar' }, [1, 6].map(n => h('button', {
        type: 'button', class: n === hours ? 'chip active' : 'chip', onclick: () => { detail.hours = n; renderDetail(); },
      }, n === 1 ? t('last1h') : t('last6h')))),
      h('div', { class: 'charts' },
        lineChart({ title: t('cpu'), points: m.points, value: p => p.cpu, format: cpuUnit, guides: guides.cpu, empty: t('noHistory') }),
        lineChart({ title: t('memory'), points: m.points, value: p => p.memory, format: bytes, guides: guides.memory, empty: t('noHistory') })));
  }, METRICS_MS);
}

// podResourcesOf sums the requests and limits of a pod's containers. A limit
// is only a limit when every container has one.
function podResourcesOf(pod) {
  const out = { reqCPU: 0, limCPU: 0, reqMem: 0, limMem: 0 };
  for (const c of (pod.spec && pod.spec.containers) || []) {
    const r = (c.resources && c.resources.requests) || {};
    const l = (c.resources && c.resources.limits) || {};
    out.reqCPU += quantity(r.cpu, true) || 0;
    out.reqMem += quantity(r.memory) || 0;
    out.limCPU = out.limCPU == null || l.cpu == null ? null : out.limCPU + (quantity(l.cpu, true) || 0);
    out.limMem = out.limMem == null || l.memory == null ? null : out.limMem + (quantity(l.memory) || 0);
  }
  return out;
}

// ---------------------------------------------------------------- detail: app metrics

// metricPorts are the ports a pod may expose metrics on: the one its
// prometheus.io/port annotation names first, then ports named like
// metrics, then the others.
function metricPorts(pod) {
  const ann = (pod.metadata && pod.metadata.annotations) || {};
  const ports = ((pod.spec && pod.spec.containers) || []).flatMap(c => (c.ports || []).map(p => ({ port: String(p.containerPort), name: p.name || c.name })));
  const out = [];
  const add = p => {
    if (/^\d+$/.test(p.port) && !out.some(x => x.port === p.port)) out.push(p);
  };
  if (ann['prometheus.io/port']) add({ port: String(ann['prometheus.io/port']), name: 'prometheus.io/port' });
  ports.filter(p => /metric|prom/i.test(p.name)).forEach(add);
  ports.forEach(add);
  return out;
}

// renderScrapeTab reads the metrics a pod exposes, through its agent; for a
// workload, those of one of its running pods, which can be switched. With
// a port known (an annotation or a declared port) the page is read at once;
// otherwise the port is typed in first. The page is read again only on
// request: its numbers change all the time, and redrawing would take away
// the filter as it is typed into.
function renderScrapeTab() {
  const { ref, obj, kind } = detail;
  if (!agentAllows('scrape')) {
    fill(els.detailBody, h('div', { class: 'empty-note' }, t('capMissing.scrape')));
    return;
  }
  // A workload is read through one of its running pods, whose own object
  // says which ports it has; the workload's template if that cannot be read.
  let source = obj;
  let pods = null;
  // Opened from a found source: read where it answered.
  const pend = pendingScrape && pendingScrape.ns === ref.ns && pendingScrape.name === ref.name ? pendingScrape : null;
  if (kind !== 'Pod') {
    const waiting = c => {
      fill(els.detailBody, c.error ? errorPanel(c.error) : h('div', { class: 'empty-note' }, t('loading')));
    };
    if (!detail.cache.ownPods) fetchInto('ownPods', () => api(clusterPath() + '/pods?namespace=' + enc(ref.ns)));
    const c = detail.cache.ownPods;
    if (c.value === undefined) return waiting(c);
    pods = c.value.filter(p => p.owner === kind + '/' + ref.name && p.phase === 'Running').map(p => p.name).sort();
    if (!pods.length) {
      fill(els.detailBody, h('div', { class: 'empty-note' }, t('noRunningPod')));
      return;
    }
    // The pod read before may have been replaced since.
    if (detail.scrape && !pods.includes(detail.scrape.pod)) detail.scrape.pod = pods[0];
    const first = detail.scrape ? detail.scrape.pod : pend && pods.includes(pend.pod) ? pend.pod : pods[0];
    const key = 'podObject ' + first;
    if (!detail.cache[key]) fetchInto(key, () => api(objectPath({ gvr: KIND_API.Pod, ns: ref.ns, name: first })));
    const p = detail.cache[key];
    if (p.value === undefined && !p.error) return waiting(p);
    source = p.value || (obj.spec && obj.spec.template) || {};
  }
  const ann = (source.metadata && source.metadata.annotations) || {};
  const ports = metricPorts(source);
  if (!detail.scrape) {
    detail.scrape = pend
      ? { port: pend.port, path: pend.path, q: '', shown: 30, asked: true, pod: pods && !pods.includes(pend.pod) ? pods[0] : pend.pod }
      : {
        port: ports.length ? ports[0].port : '', path: ann['prometheus.io/path'] || '/metrics', q: '', shown: 30,
        asked: ports.length > 0, pod: pods ? pods[0] : ref.name,
      };
    pendingScrape = null;
  }
  const s = detail.scrape;
  const podPick = pods ? h('select', {
    'aria-label': t('pods'),
    onchange: e => {
      s.pod = e.target.value;
      renderDetail();
    },
  }, pods.map(p => h('option', { value: p, selected: p === s.pod }, p))) : null;
  const portIn = h('input', { type: 'text', inputmode: 'numeric', class: 'port-input', value: s.port, list: 'scrape-ports', placeholder: t('port'), 'aria-label': t('port') });
  const pathIn = h('input', { type: 'text', class: 'mono path-input', value: s.path, placeholder: '/metrics', 'aria-label': t('path') });
  const read = () => {
    s.port = portIn.value.trim();
    s.path = pathIn.value.trim() || '/metrics';
    s.asked = true;
    delete detail.cache['scrape ' + s.pod + ' ' + s.port + ' ' + s.path];
    renderDetail();
  };
  const onEnter = e => {
    if (e.key === 'Enter') read();
  };
  portIn.addEventListener('keydown', onEnter);
  pathIn.addEventListener('keydown', onEnter);
  const list = h('div');
  const toolbar = h('div', { class: 'detail-toolbar' },
    podPick, portIn, h('datalist', { id: 'scrape-ports' }, ports.map(p => h('option', { value: p.port }, p.name))), pathIn,
    button(t('readMetrics'), read),
    s.asked ? h('input', {
      type: 'text', class: 'filter', value: s.q, placeholder: t('metricsFilter'), 'aria-label': t('metricsFilter'),
      oninput: e => {
        s.q = e.target.value;
        s.shown = 30;
        drawList();
      },
    }) : null);
  if (!s.asked) {
    fill(els.detailBody, toolbar, h('p', { class: 'muted' }, t('scrapeHint')));
    return;
  }
  const key = 'scrape ' + s.pod + ' ' + s.port + ' ' + s.path;
  if (!detail.cache[key]) {
    const q = new URLSearchParams({ port: s.port, path: s.path });
    fetchInto(key, () => api(clusterPath() + '/namespaces/' + enc(ref.ns) + '/pods/' + enc(s.pod) + '/scrape?' + q));
  }
  const c = detail.cache[key];
  const drawList = () => {
    if (c.error || c.value === undefined) {
      fill(list, c.error ? errorPanel(c.error) : h('div', { class: 'empty-note' }, t('loading')));
      return;
    }
    const page = c.value;
    const words = s.q.toLowerCase().split(/\s+/).filter(Boolean);
    const fams = page.families.filter(f => matches(words, [f.name, f.help, f.type])).sort((a, b) => cmp(a.name, b.name));
    const owner = kind === 'Pod' ? podOwner(obj) : kind + '/' + ref.name;
    const onWatch = canIn('operator', ref.ns)
      ? f => () => watchDialog({ ns: ref.ns, owner, pod: s.pod, family: f, port: s.port, path: s.path })
      : null;
    fill(list,
      page.truncated ? h('div', { class: 'more-note' }, t('truncatedMetrics')) : null,
      fams.length ? null : h('div', { class: 'empty-note' }, page.families.length ? t('noMatch') : t('noMetricsHere')),
      fams.slice(0, s.shown).map(f => metricFamily(f, onWatch && onWatch(f))),
      fams.length > s.shown ? h('div', { class: 'more-note' }, button(t('moreMetrics', Math.min(100, fams.length - s.shown)), () => {
        s.shown += 100;
        drawList();
      })) : null);
  };
  fill(els.detailBody, toolbar, list);
  drawList();
}

// metricFamily shows one metric of a pod's page: its samples, a few of
// them when there are many, and a way to watch it.
function metricFamily(f, onWatch) {
  const rows = f.samples.slice(0, 20);
  return h('div', { class: 'metric-family' },
    h('div', { class: 'metric-head' },
      h('div', { class: 'what' },
        h('span', { class: 'mono metric-name' }, f.name), ' ', h('span', { class: 'metric-type' }, f.type),
        f.samples.length > 1 ? h('span', { class: 'muted small-text' }, ' ' + t('nSeries', f.samples.length)) : null,
        f.help ? h('div', { class: 'muted small-text' }, f.help) : null),
      onWatch ? button(t('watch'), onWatch) : null),
    rows.length ? h('table', { class: 'metric-samples' }, h('tbody', null, rows.map(s => h('tr', null,
      h('td', null, h('div', { class: 'chips' },
        s.name !== f.name ? h('span', { class: 'mono muted small-text' }, s.name.startsWith(f.name) ? s.name.slice(f.name.length) : s.name) : null,
        Object.keys(s.labels || {}).sort().map(k => h('span', { class: 'label-chip' }, k + '=' + s.labels[k])))),
      h('td', { class: 'num mono' }, sampleValue(s)))))) : null,
    f.samples.length > rows.length ? h('div', { class: 'muted small-text' }, t('moreSeries', f.samples.length - rows.length)) : null);
}

function sampleValue(s) {
  const v = s.value;
  if (typeof v !== 'number') return String(v);
  const text = Number.isInteger(v) ? String(v) : String(+v.toPrecision(7));
  return /_bytes(_total)?$/.test(s.name) && v >= 1024 ? text + ' (' + bytes(v) + ')' : text;
}

// ---------------------------------------------------------------- detail: logs

function containersOf(pod) {
  return ((pod.spec && pod.spec.containers) || []).map(c => c.name);
}
// logContainers are the containers with logs: init containers first, as
// they run first; a failing init container is a common reason a pod hangs.
function logContainers(pod) {
  const spec = pod.spec || {};
  return [...(spec.initContainers || []).map(c => ({ name: c.name, init: true })), ...(spec.containers || []).map(c => ({ name: c.name, init: false }))];
}
function statusOf(pod, container) {
  const st = pod.status || {};
  return [...(st.initContainerStatuses || []), ...(st.containerStatuses || [])].find(c => c.name === container);
}
function restartsOf(pod, container) {
  const s = statusOf(pod, container);
  return s ? s.restartCount || 0 : 0;
}
// firstTrouble picks the container to show first: one that keeps
// restarting or is not ready, else the first regular container.
function firstTrouble(pod) {
  const st = pod.status || {};
  const all = [...(st.initContainerStatuses || []), ...(st.containerStatuses || [])];
  const bad = all.find(c => c.state && c.state.waiting && c.state.waiting.reason && c.state.waiting.reason !== 'PodInitializing') ||
    (st.containerStatuses || []).find(c => !c.ready);
  return bad ? bad.name : containersOf(pod)[0] || '';
}

function renderLogsTab() {
  const pod = detail.obj;
  const all = logContainers(pod);
  if (!detail.logs) {
    detail.logs = {
      container: firstTrouble(pod), previous: false, tail: 500, follow: false, timestamps: true, wrap: true,
      search: '', only: false, text: null, error: null, busy: false, seq: 0, current: 0,
    };
    fetchLogs();
  }
  const L = detail.logs;
  const view = h('div', { class: 'logview' + (L.wrap ? ' wrap' : ''), tabindex: '0' });
  els.logView = view;
  els.logCount = h('span', { class: 'muted log-count' });
  const restarts = L.container === '*' ? 0 : restartsOf(pod, L.container);
  const opt = (label, value, on) => h('label', { class: 'check' },
    h('input', { type: 'checkbox', checked: value, onchange: e => on(e.target.checked) }), label);
  const pick = h('select', {
    'aria-label': t('container'),
    onchange: e => {
      L.container = e.target.value;
      L.previous = L.previous && L.container !== '*';
      L.text = null;
      fetchLogs();
      renderDetail();
    },
  },
  all.map(c => h('option', { value: c.name, selected: c.name === L.container }, c.name + (c.init ? ' (init)' : ''))),
  all.length > 1 ? h('option', { value: '*', selected: L.container === '*' }, t('allContainers')) : null);
  const search = h('input', {
    type: 'text', class: 'filter', value: L.search, placeholder: t('searchLogs'), 'aria-label': t('searchLogs'),
    oninput: e => {
      L.search = e.target.value;
      L.current = 0;
      drawLogs({ jump: true });
    },
    onkeydown: e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        stepMatch(e.shiftKey ? -1 : 1);
      }
    },
  });
  const file = detail.ref.name + (L.container && L.container !== '*' ? '-' + L.container : '') + (L.previous ? '-previous' : '') + '.log';
  fill(els.detailBody,
    h('div', { class: 'detail-toolbar' },
      pick,
      L.container === '*' ? null : opt(t('previous'), L.previous, v => { L.previous = v; L.text = null; fetchLogs(); renderDetail(); }),
      h('select', { 'aria-label': t('lastN', '…'), onchange: e => { L.tail = Number(e.target.value); fetchLogs(); } },
        [100, 500, 2000, 5000].map(n => h('option', { value: String(n), selected: n === L.tail }, t('lastN', n)))),
      opt(t('follow'), L.follow, v => { L.follow = v; startFollow(); if (v) fetchLogs(); }),
      opt(t('timestamps'), L.timestamps, v => { L.timestamps = v; drawLogs(); }),
      opt(t('wrap'), L.wrap, v => { L.wrap = v; view.classList.toggle('wrap', v); }),
      h('span', { class: 'toolbar-end' },
        h('button', { type: 'button', class: 'icon-btn', title: t('refresh'), onclick: fetchLogs }, '↻'),
        button(t('copy'), () => copyText(L.text || '')),
        button(t('download'), () => download(L.text || '', file)))),
    h('div', { class: 'detail-toolbar' }, search,
      h('button', { type: 'button', class: 'icon-btn small', title: 'Shift+Enter', onclick: () => stepMatch(-1) }, '↑'),
      h('button', { type: 'button', class: 'icon-btn small', title: 'Enter', onclick: () => stepMatch(1) }, '↓'),
      els.logCount, opt(t('onlyMatches'), L.only, v => { L.only = v; drawLogs({ jump: true }); })),
    restarts && !L.previous ? h('div', { class: 'banner' }, '↺ ', t('restartedHint', restarts), ' ',
      button(t('showPrevious'), () => { L.previous = true; L.text = null; fetchLogs(); renderDetail(); }, 'small')) : null,
    view);
  drawLogs({ first: true });
  startFollow();
}

function logPath(container, previous, tail) {
  const q = new URLSearchParams({ tail: String(tail) });
  if (container) q.set('container', container);
  if (previous) q.set('previous', 'true');
  return clusterPath() + '/namespaces/' + enc(detail.ref.ns) + '/pods/' + enc(detail.ref.name) + '/logs?' + q;
}

// A line starts with the timestamp the agent asks Kubernetes for.
const STAMP = /^(\d{4}-\d\d-\d\dT[0-9:.]+Z) /;
const LEVEL_ERROR = /\b(ERROR|ERR|FATAL|PANIC|CRIT|CRITICAL|panic|Exception|Traceback)\b|level=(error|fatal)|"level":"(error|fatal)"/;
const LEVEL_WARN = /\b(WARN|WARNING)\b|level=warn|"level":"warn/;

async function fetchLogs() {
  const L = detail.logs;
  if (!L) return;
  const d = detail;
  const my = ++L.seq;
  L.busy = true;
  try {
    let text;
    if (L.container === '*') {
      // Every container's lines, merged in time order and labelled.
      const names = logContainers(d.obj).map(c => c.name);
      const parts = await Promise.all(names.map(n => api(logPath(n, false, L.tail), { text: true }).then(s => ({ n, s }), () => ({ n, s: '' }))));
      const lines = [];
      for (const { n, s } of parts) {
        for (const line of s.split('\n')) {
          if (line) lines.push({ at: Date.parse((line.match(STAMP) || [])[1]) || 0, text: line.replace(STAMP, (m, ts) => ts + ' [' + n + '] ') });
        }
      }
      lines.sort((a, b) => a.at - b.at);
      text = lines.map(l => l.text).join('\n');
    } else {
      text = await api(logPath(L.container, L.previous, L.tail), { text: true });
    }
    if (detail !== d || L.seq !== my) return;
    L.error = null;
    if (text === L.text) return;
    L.text = text;
  } catch (e) {
    if (detail !== d || L.seq !== my) return;
    L.error = e.message;
    L.text = null;
  } finally {
    if (L.seq === my) L.busy = false;
  }
  drawLogs();
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// drawLogs renders the lines, levels coloured and search matches marked. It
// stays at the bottom while the reader is there, and otherwise keeps still:
// only a new search (jump) moves to its first match.
function drawLogs({ first = false, jump = false } = {}) {
  const L = detail.logs;
  const view = els.logView;
  if (!L || !view || !view.isConnected) return;
  const atBottom = first || view.scrollHeight - view.scrollTop - view.clientHeight < 40;
  const top = view.scrollTop;
  view.replaceChildren();
  if (els.logCount) els.logCount.textContent = '';
  if (L.error) {
    view.append(h('div', { class: 'log-error' }, t('failed') + ': ' + L.error));
    return;
  }
  if (L.text == null) {
    view.append(h('div', { class: 'log-note' }, t('loading')));
    return;
  }
  const lines = L.text.split('\n');
  if (lines.length && lines[lines.length - 1] === '') lines.pop();
  if (!lines.length) {
    view.append(h('div', { class: 'log-note' }, t('noLogs')));
    return;
  }
  const re = L.search ? new RegExp(escapeRegExp(L.search), 'gi') : null;
  const frag = document.createDocumentFragment();
  for (const raw of lines) {
    const line = L.timestamps ? raw : raw.replace(STAMP, '');
    re && (re.lastIndex = 0);
    const hit = re ? re.test(line) : false;
    if (L.only && re && !hit) continue;
    const row = document.createElement('div');
    row.className = LEVEL_ERROR.test(line) ? 'log-line lv-error' : LEVEL_WARN.test(line) ? 'log-line lv-warn' : 'log-line';
    if (hit) {
      let last = 0;
      re.lastIndex = 0;
      for (let m = re.exec(line); m; m = re.exec(line)) {
        row.append(line.slice(last, m.index));
        const mark = document.createElement('mark');
        mark.textContent = m[0];
        row.append(mark);
        last = m.index + m[0].length;
      }
      row.append(line.slice(last));
    } else {
      row.textContent = line || ' ';
    }
    frag.append(row);
  }
  view.append(frag);
  if (re) {
    const n = view.querySelectorAll('mark').length;
    if (!n) els.logCount.textContent = t('noMatches');
    else markCurrent(jump || first);
    if (jump || first) return;
  }
  view.scrollTop = atBottom ? view.scrollHeight : top;
}

// markCurrent highlights the current match, scrolling to it when asked.
function markCurrent(scroll) {
  const marks = els.logView.querySelectorAll('mark');
  if (!marks.length) return;
  const L = detail.logs;
  L.current = ((L.current % marks.length) + marks.length) % marks.length;
  marks.forEach((m, i) => m.classList.toggle('current', i === L.current));
  if (scroll) marks[L.current].scrollIntoView({ block: 'center' });
  if (els.logCount) els.logCount.textContent = (L.current + 1) + ' / ' + marks.length;
}

function stepMatch(delta) {
  if (!detail.logs || !detail.logs.search) return;
  detail.logs.current += delta;
  markCurrent(true);
}

function startFollow() {
  clearInterval(detail.followTimer);
  if (detail.logs && detail.logs.follow) {
    const d = detail;
    d.followTimer = setInterval(() => {
      if (detail === d && !document.hidden && !d.logs.busy && currentTab() === 'logs') fetchLogs();
    }, FOLLOW_MS);
  }
}
function stopFollow() {
  clearInterval(detail.followTimer);
}

// ---------------------------------------------------------------- detail: console

// Commands run one at a time through the agent, without a terminal. A small
// wrapper keeps the working directory between them: the command runs in it,
// and the directory it ends in comes back after a \x1f marker.
function consoleScript(command) {
  return 'cd "$1" 2>/dev/null || cd /\n' + command + '\n__kg=$?\nprintf \'\\n\\037%s\' "$(pwd)"\nexit $__kg';
}

function renderConsoleTab() {
  const pod = detail.obj;
  const names = containersOf(pod);
  if (!detail.console) detail.console = { container: names[0] || '', cwd: '/', history: [], at: -1, lines: [], busy: false };
  const C = detail.console;
  const out = h('div', { class: 'console-out', tabindex: '0' });
  const input = h('input', { type: 'text', class: 'console-input', spellcheck: 'false', autocomplete: 'off', 'aria-label': t('run') });
  const prompt = h('span', { class: 'console-prompt' }, C.container + ':' + C.cwd + ' $');
  const draw = () => {
    out.replaceChildren(...C.lines.map(l => h('div', { class: 'cl-' + l.kind }, l.text)));
    out.scrollTop = out.scrollHeight;
    prompt.textContent = C.container + ':' + C.cwd + ' $';
  };
  const run = async () => {
    const command = input.value.trim();
    if (!command || C.busy) return;
    if (command === 'clear') {
      C.lines = [];
      input.value = '';
      draw();
      return;
    }
    C.history.push(command);
    C.at = C.history.length;
    C.lines.push({ kind: 'cmd', text: C.container + ':' + C.cwd + ' $ ' + command });
    input.value = '';
    C.busy = true;
    draw();
    try {
      const res = await api(clusterPath() + '/namespaces/' + enc(detail.ref.ns) + '/pods/' + enc(detail.ref.name) + '/exec', {
        method: 'POST', body: { container: C.container, command: ['sh', '-c', consoleScript(command), 'kartal', C.cwd] },
      });
      let stdout = res.stdout || '';
      const at = stdout.lastIndexOf('\n\x1f');
      if (at >= 0) {
        C.cwd = stdout.slice(at + 2).trim() || C.cwd;
        stdout = stdout.slice(0, at);
      }
      if (stdout) C.lines.push({ kind: 'out', text: stdout.replace(/\n$/, '') });
      if (res.stderr) C.lines.push({ kind: 'err', text: res.stderr.replace(/\n$/, '') });
      if (res.exitCode) C.lines.push({ kind: 'info', text: t('exitCode', res.exitCode) });
      if (res.truncated) C.lines.push({ kind: 'info', text: t('truncated') });
    } catch (e) {
      if (e.status !== 401) C.lines.push({ kind: 'err', text: /executable file not found|no such file or directory/.test(e.message) ? t('noShell') + ' (' + e.message + ')' : e.message });
    }
    C.busy = false;
    draw();
    input.focus();
  };
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      run();
    } else if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
      e.preventDefault();
      C.at = Math.max(0, Math.min(C.history.length, C.at + (e.key === 'ArrowUp' ? -1 : 1)));
      input.value = C.history[C.at] || '';
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      C.lines = [];
      draw();
    }
  });
  const allowed = agentAllows('exec');
  fill(els.detailBody,
    h('div', { class: 'detail-toolbar' },
      names.length > 1 ? h('select', { onchange: e => { C.container = e.target.value; C.cwd = '/'; draw(); } }, names.map(n => h('option', { value: n, selected: n === C.container }, n))) : null,
      button(t('clear'), () => { C.lines = []; draw(); })),
    h('p', { class: 'muted' }, allowed ? t('consoleHint') : t('capMissing.exec')),
    out,
    allowed ? h('div', { class: 'console-line' }, prompt, input) : null);
  draw();
  if (allowed) input.focus();
}

// ---------------------------------------------------------------- command palette

function paletteItems() {
  const out = [];
  const add = (kind, label, run) => out.push({ kind, label, run, search: (kind + ' ' + label).toLowerCase() });
  for (const ns of favs.ns) {
    add('★ ' + t('pods'), ns, () => go({ view: 'pods', ns }));
    add('★ ' + t('events'), ns, () => go({ view: 'events', ns }));
  }
  for (const key of favs.obj) {
    const { kind, ns, name } = splitKey(key);
    const gvr = KIND_API[kind];
    add('★ ' + kind, (ns ? ns + '/' : '') + name, () => (gvr ? openDetail({ gvr, ns, name }) : go({ view: KIND_VIEW[kind] || 'resources', ns, q: name })));
  }
  for (const id of VIEWS) {
    if ((id === 'audit' && !roleAtLeast('operator')) || (id === 'nodes' && !roleIn(''))) continue;
    add(t('view'), t(id), () => go({ view: id }));
  }
  for (const n of state.namespaces || []) {
    if (favs.ns.includes(n.name)) continue;
    add(t('pods'), n.name, () => go({ view: 'pods', ns: n.name }));
    add(t('events'), n.name, () => go({ view: 'events', ns: n.name }));
    add(t('namespace'), n.name, () => selectNamespace(n.name));
  }
  for (const c of state.clusters || []) add(t('cluster'), c.name, () => go({ cluster: c.name, view: state.view, ns: '' }));
  const items = state.data && state.data.items;
  if (TABLES[state.view] && items) {
    for (const it of items.slice(0, 3000)) {
      const name = it.name || it.secret;
      if (!name) continue;
      const label = (it.namespace ? it.namespace + '/' : '') + name;
      if (state.view === 'pods') {
        add(t('logs'), label, () => openDetail({ gvr: KIND_API.Pod, ns: it.namespace, name: it.name }, 'logs'));
        add(t('details'), label, () => openDetail({ gvr: KIND_API.Pod, ns: it.namespace, name: it.name }));
      } else {
        const kind = it.kind || { services: 'Service', ingresses: 'Ingress', configmaps: 'ConfigMap', secrets: 'Secret', certificates: 'Secret', volumeclaims: 'PersistentVolumeClaim', jobs: 'Job', cronjobs: 'CronJob', nodes: 'Node' }[state.view];
        const gvr = KIND_API[kind];
        add(t(state.view), label, () => (gvr ? openDetail({ gvr, ns: it.namespace || '', name }) : go({ q: name })));
      }
    }
  }
  add(t('action'), t('toggleTheme'), toggleTheme);
  add(t('action'), t('language'), toggleLang);
  return out;
}

function openPalette() {
  if (!els.shell || document.querySelector('.palette')) return;
  const items = paletteItems();
  let shown = [];
  let selected = 0;
  const input = h('input', { type: 'text', placeholder: t('paletteHint'), 'aria-label': t('search') });
  const list = h('ul', { role: 'listbox' });
  const close = () => overlay.remove();
  const run = it => { close(); it.run(); };
  const highlight = () => {
    Array.from(list.children).forEach((li, i) => li.classList.toggle('selected', i === selected));
    const li = list.children[selected];
    if (li) li.scrollIntoView({ block: 'nearest' });
  };
  const update = () => {
    const words = input.value.toLowerCase().split(/\s+/).filter(Boolean);
    shown = items.filter(it => words.every(w => it.search.includes(w))).slice(0, 60);
    selected = 0;
    fill(list, shown.length ? shown.map((it, i) => h('li', {
      role: 'option', onclick: () => run(it),
      onmousemove: () => { if (selected !== i) { selected = i; highlight(); } },
    }, h('span', { class: 'kind' }, it.kind), h('span', { class: 'label' }, it.label))) : h('li', { class: 'muted' }, t('noMatch')));
    highlight();
  };
  input.addEventListener('input', update);
  input.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      selected = Math.max(0, Math.min(shown.length - 1, selected + (e.key === 'ArrowDown' ? 1 : -1)));
      highlight();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (shown[selected]) run(shown[selected]);
    } else if (e.key === 'Escape') {
      // Close only the palette, not the panels behind it as well.
      e.preventDefault();
      e.stopPropagation();
      close();
    }
  });
  const overlay = h('div', { class: 'overlay', onclick: e => { if (e.target === overlay) close(); } },
    h('div', { class: 'palette', role: 'dialog', 'aria-label': t('search') }, input, list, h('div', { class: 'hint' }, t('paletteKeys'))));
  document.body.append(overlay);
  update();
  input.focus();
}

// ---------------------------------------------------------------- sign-in, theme, language

// loginMethods is what the server offers besides tokens: a user name and
// password (its directory), asked for once.
let loginMethods = null;

async function showLogin(message) {
  // Several requests can fail at once; keep the form (and its message) that
  // is already up.
  if (!els.shell && !message && root.querySelector('.login')) return;
  stopRefresh();
  resetDetail();
  els.shell = null;
  els.top = els.side = els.head = els.banner = els.content = els.detail = els.filter = els.updated = null;
  els.nsPicker = els.nsMenuList = els.pinned = els.nav = null;
  state.nsMenuOpen = false;
  state.me = null;
  if (!loginMethods) {
    try {
      const res = await fetch('api/v1/login', { headers: { Accept: 'application/json' }, cache: 'no-cache' });
      loginMethods = res.ok ? await res.json() : { password: false };
    } catch {
      loginMethods = { password: false };
    }
  }
  renderLogin(message, loginMethods.password ? 'password' : 'token');
}

// renderLogin asks for a user name and password, or for a token.
function renderLogin(message, mode) {
  const withPassword = mode === 'password';
  const user = h('input', { type: 'text', required: true, autocomplete: 'username', spellcheck: 'false', 'aria-label': t('userName') });
  const secret = h('input', { type: 'password', required: true, autocomplete: 'current-password', 'aria-label': withPassword ? t('password') : t('token') });
  const remember = h('input', { type: 'checkbox' });
  const error = h('div', { class: 'error', role: 'alert' }, message || '');
  const submit = h('button', { type: 'submit', class: 'btn primary' }, t('signIn'));
  const form = h('form', {
    onsubmit: async e => {
      e.preventDefault();
      submit.disabled = true;
      error.textContent = '';
      try {
        if (withPassword) {
          const res = await fetch('api/v1/login', {
            method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({ username: user.value, password: secret.value }),
          });
          const answer = await res.json().catch(() => ({}));
          if (!res.ok) throw new ApiError(res.status, answer.error || res.status + ' ' + res.statusText);
          setToken(answer.token, remember.checked);
        } else {
          setToken(secret.value.trim(), remember.checked);
          await api('clusters');
        }
        startApp();
      } catch (err) {
        // A rejected token already brought back a fresh sign-in form.
        if (withPassword || err.status !== 401) {
          error.textContent = err.message;
          submit.disabled = false;
          secret.value = '';
          secret.focus();
        }
      }
    },
  },
  h('h1', null, h('img', { src: '_ui/eagle.svg', alt: '' }), 'Kartal Gözü'),
  withPassword
    ? h('label', { class: 'field' }, t('userName'), user)
    // A password manager keeps the token under this name.
    : h('input', { type: 'text', name: 'username', autocomplete: 'username', value: 'Kartal Gözü', hidden: true, 'aria-hidden': 'true', tabindex: '-1' }),
  h('label', { class: 'field' }, withPassword ? t('password') : t('token'), secret),
  h('div', { class: 'muted' }, withPassword ? t('passwordHelp') : t('tokenHelp')),
  h('label', null, remember, t('remember')),
  error, submit,
  loginMethods && loginMethods.password ? h('button', {
    type: 'button', class: 'link-button small-text', onclick: () => renderLogin('', withPassword ? 'token' : 'password'),
  }, withPassword ? t('useToken') : t('usePassword')) : null);
  fill(root, h('div', { class: 'login' }, form));
  (withPassword ? user : secret).focus();
}

async function logout() {
  if (!(await leaveEditor())) return;
  // A password sign-in has a session on the server; end it there too.
  const token = getToken();
  if (token.startsWith('kgs_')) {
    fetch('api/v1/logout', { method: 'POST', headers: { Authorization: 'Bearer ' + token } }).catch(() => {});
  }
  setToken('', false);
  showLogin('');
}

function theme() {
  return document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
}
function toggleTheme() {
  const next = theme() === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  writeStore('localStorage', 'kartal.theme', next);
  renderTop();
}
async function toggleLang() {
  // Switching redraws everything, the YAML being edited too.
  if (!(await leaveEditor())) return;
  lang = lang === 'tr' ? 'en' : 'tr';
  writeStore('localStorage', 'kartal.lang', lang);
  document.documentElement.lang = lang;
  if (els.shell) startApp();
}

// ---------------------------------------------------------------- start

function isTyping(el) {
  return el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable);
}

document.addEventListener('keydown', e => {
  if (!els.shell) return;
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    openPalette();
  } else if (e.key === 'Escape' && !document.querySelector('.overlay')) {
    // Escape first leaves a field in the panel, then closes the panel.
    if (state.nsMenuOpen) closeNsMenu();
    else if (state.obj && isTyping(e.target) && els.detail.contains(e.target)) e.target.blur();
    else if (state.obj) closeDetail();
    else els.shell.classList.remove('side-open');
  } else if (e.key === '/' && !isTyping(e.target) && els.filter) {
    e.preventDefault();
    els.filter.focus();
  }
});
// A click anywhere outside the namespace picker closes its list.
document.addEventListener('mousedown', e => {
  if (state.nsMenuOpen && els.nsPicker && !els.nsPicker.contains(e.target)) closeNsMenu();
});
window.addEventListener('hashchange', () => { if (els.shell) onRoute(); });
// Leaving the page with unsaved YAML edits asks first.
window.addEventListener('beforeunload', e => {
  if (detail && detail.editing && detail.editing.text !== detail.editing.original) e.preventDefault();
});
window.addEventListener('storage', e => {
  if (els.shell && e.key === favKey()) {
    favs = readFavs();
    refreshSide(true);
    renderContent();
  }
});
document.addEventListener('visibilitychange', () => {
  if (els.shell && !document.hidden) refresh({ auto: true });
});
// Draw what a refresh brought in while text was selected, once it is not.
document.addEventListener('selectionchange', () => {
  if (state.dirty && !selectionInside(els.content)) renderContent();
});

document.documentElement.dataset.theme = readStore('localStorage', 'kartal.theme') ||
  (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
document.documentElement.lang = lang;
startApp();
