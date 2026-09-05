import HeroSection from '../components/HeroSection.jsx'
import FeaturesSection from '../components/FeaturesSection.jsx'
import HowItWorksSection from '../components/HowItWorksSection.jsx'

// The Home page. The shared Navbar and Footer come from Layout.jsx.
// Each page component only renders its own content.
function HomePage() {
  return (
    <>
      <HeroSection />
      <FeaturesSection />
      <HowItWorksSection />
    </>
  )
}

export default HomePage
