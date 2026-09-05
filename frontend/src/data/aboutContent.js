// ---------------------------------------------------------------------------
// Static content for the About PhishGuard page (version 5).
// All copy is sample/static — no backend or model is connected yet.
// ---------------------------------------------------------------------------

export const aboutHeader = {
  heading: 'About PhishGuard',
  subtitle:
    'Understanding phishing threats through intelligent URL security analysis.',
}

export const whatIsPhishing = {
  icon: 'bi-exclamation-triangle',
  title: 'What is Phishing?',
  text: 'Phishing is a cyberattack technique in which attackers use deceptive websites, messages, or URLs to trick users into revealing sensitive information such as usernames, passwords, or financial details.',
}

export const whatIsPhishGuard = {
  icon: 'bi-shield-fill-check',
  title: 'What is PhishGuard?',
  text: 'PhishGuard is a URL security analysis system designed to identify potential phishing URLs by analyzing URL characteristics and combining machine learning predictions with security-based rules.',
  purposes: [
    'Security awareness',
    'URL risk assessment',
    'Educational cybersecurity analysis',
    'Early identification of suspicious URLs',
  ],
}

// The five-step pipeline shown in "How PhishGuard Works".
export const analysisSteps = [
  {
    number: '01',
    icon: 'bi-link-45deg',
    title: 'User Enters URL',
    text: 'Paste any link into the analyzer to start a scan.',
  },
  {
    number: '02',
    icon: 'bi-list-check',
    title: 'URL Feature Extraction',
    text: 'The URL is broken into characteristics such as length, special characters, domain and subdomains.',
  },
  {
    number: '03',
    icon: 'bi-cpu',
    title: 'Machine Learning Analysis',
    text: 'A trained model scores the URL against patterns found in known phishing attacks.',
  },
  {
    number: '04',
    icon: 'bi-shield-exclamation',
    title: 'Security Rule Analysis',
    text: 'Built-in cybersecurity rules flag suspicious structures and behaviors.',
  },
  {
    number: '05',
    icon: 'bi-speedometer2',
    title: 'Risk Assessment',
    text: 'All signals combine into one clear, explainable risk verdict.',
  },
]

export const techStack = [
  {
    icon: 'bi-window-stack',
    tile: 'cyan',
    layer: 'Frontend',
    tech: 'React.js + Bootstrap 5',
    note: 'Responsive user interface',
  },
  {
    icon: 'bi-server',
    tile: 'violet',
    layer: 'Backend',
    tech: 'Python + FastAPI',
    note: 'Analysis API service',
  },
  {
    icon: 'bi-cpu',
    tile: 'emerald',
    layer: 'Machine Learning',
    tech: 'Phishing URL Detection Model + ONNX Runtime',
    note: 'Fast, portable model inference',
  },
  {
    icon: 'bi-database',
    tile: 'amber',
    layer: 'Database',
    tech: 'SQLite + SQLAlchemy',
    note: 'Stores scan history',
  },
  {
    icon: 'bi-arrow-left-right',
    tile: 'red',
    layer: 'API Communication',
    tech: 'Axios',
    note: 'HTTP client between UI and API',
  },
]

export const securityFeatures = [
  {
    icon: 'bi-robot',
    tile: 'violet',
    title: 'Machine Learning Detection',
    text: 'Analyzes URL characteristics using a trained phishing URL classification model.',
  },
  {
    icon: 'bi-radar',
    tile: 'cyan',
    title: 'URL Feature Analysis',
    text: 'Examines URL structure, length, special characters, domains, subdomains and other characteristics.',
  },
  {
    icon: 'bi-list-check',
    tile: 'amber',
    title: 'Rule-Based Security Checks',
    text: 'Identifies suspicious patterns using predefined cybersecurity rules.',
  },
  {
    icon: 'bi-speedometer2',
    tile: 'red',
    title: 'Risk Assessment',
    text: 'Combines analysis results to provide an understandable security classification.',
  },
]

export const securityNotice = {
  icon: 'bi-exclamation-octagon-fill',
  title: 'Important Security Notice',
  text: 'PhishGuard provides a security assessment based on URL characteristics and machine learning analysis. A SAFE result does not guarantee that a website is completely secure. Users should always exercise caution when visiting unfamiliar websites.',
}

// Vertically-ordered steps for the architecture diagram. Steps marked with
// `branch: true` render two parallel boxes (model + rules).
export const architecture = [
  { icon: 'bi-person', label: 'User' },
  { icon: 'bi-window-stack', label: 'React Frontend' },
  { icon: 'bi-arrow-left-right', label: 'Axios API Request' },
  { icon: 'bi-server', label: 'FastAPI Backend' },
  { icon: 'bi-list-check', label: 'URL Feature Extraction' },
  {
    branch: true,
    boxes: [
      { icon: 'bi-cpu', label: 'Machine Learning Model' },
      { icon: 'bi-shield-exclamation', label: 'Security Rule Engine' },
    ],
  },
  { icon: 'bi-speedometer2', label: 'Risk Assessment' },
  { icon: 'bi-clipboard-check', label: 'Analysis Result', highlight: true },
]

export const projectInfo = [
  {
    label: 'Project',
    value: 'PhishGuard – Phishing URL Detection & Security Analyzer',
  },
  { label: 'Category', value: 'Cybersecurity + Machine Learning' },
  { label: 'Purpose', value: 'Educational and security analysis' },
]
