// ---------------------------------------------------------------------------
// Sample / static content for the PhishGuard landing page (version 2).
// Keeping this content separate from the components makes it easy to edit
// copy later or replace it with data fetched from the FastAPI backend.
// ---------------------------------------------------------------------------

export const brand = {
  name: 'PhishGuard',
  tagline:
    'Phishing URL detection & security analyzer powered by machine learning.',
}

// Navbar links. "Analyze URL" navigates to the home page scanner.
export const navLinks = [
  { label: 'Home', path: '/' },
  { label: 'Analyze URL', path: '/' },
  { label: 'Dashboard', path: '/dashboard' },
  { label: 'Scan History', path: '/history' },
  { label: 'About', path: '/about' },
]

export const hero = {
  badge: 'AI-Powered Phishing Protection',
  titleStart: 'Detect Phishing URLs',
  titleAccent: 'Before They Harm You',
  description:
    'PhishGuard inspects every link for suspicious patterns, lookalike domains and risky behavior — combining machine learning with security rules to warn you before you click.',
  inputPlaceholder: 'Enter a URL, e.g. https://example.com',
  samples: [
    { label: 'https://www.paypal.com', kind: 'Looks safe' },
    { label: 'http://paypal-secure-login.xyz/verify', kind: 'Looks suspicious' },
  ],
  trustPoints: [
    { icon: 'bi-shield-check', text: 'No sign-up required' },
    { icon: 'bi-incognito', text: 'Private by design' },
    { icon: 'bi-lightning-charge-fill', text: 'Instant results' },
  ],
}

export const features = {
  eyebrow: 'Why PhishGuard',
  title: 'Powerful protection, simple to use',
  subtitle:
    'Every URL gets the same deep inspection a security analyst would run manually — in seconds.',
  cards: [
    {
      icon: 'bi-cpu',
      accent: 'cyan',
      title: 'Machine Learning Detection',
      description:
        'A model trained on millions of real and phishing URLs learns to spot obfuscation tricks, lookalike domains and other patterns attackers rely on.',
    },
    {
      icon: 'bi-radar',
      accent: 'violet',
      title: 'URL Security Analysis',
      description:
        'Each link is dissected for unsafe protocols, suspicious subdomains, redirect chains and other phishing indicators hidden in plain sight.',
    },
    {
      icon: 'bi-speedometer2',
      accent: 'amber',
      title: 'Risk Assessment',
      description:
        'Get a clear, human-readable risk score with the reasons behind it, so you can confidently decide whether to click or block.',
    },
  ],
}

export const steps = {
  eyebrow: 'How it works',
  title: 'From URL to verdict in seconds',
  subtitle:
    'No technical knowledge required. Paste a link and let PhishGuard do the hard work.',
  items: [
    {
      number: '01',
      icon: 'bi-link-45deg',
      title: 'Enter URL',
      description:
        'Paste any link — a login page from an unexpected email, a shortened redirect or a message from a stranger.',
    },
    {
      number: '02',
      icon: 'bi-search',
      title: 'Analyze Security Features',
      description:
        'Our engine inspects the domain, its structure and behavior signals, comparing them against known phishing indicators.',
    },
    {
      number: '03',
      icon: 'bi-123',
      title: 'Get Risk Assessment',
      description:
        'Receive an instant verdict with a risk score and a clear explanation of exactly what was found and why.',
    },
  ],
}

export const footer = {
  description:
    'PhishGuard is an open learning project that demonstrates how machine learning can protect people from phishing attacks on the modern web.',
  columns: [
    {
      heading: 'Product',
      links: [
        { label: 'Home', path: '/' },
        { label: 'Analyze URL', path: '/' },
        { label: 'Dashboard', path: '/dashboard' },
        { label: 'Scan History', path: '/history' },
      ],
    },
    {
      heading: 'Company',
      links: [
        { label: 'About', path: '/about' },
        { label: 'How It Works', path: '/' },
      ],
    },
  ],
  copyright: 'PhishGuard. All rights reserved.',
}
