import React, { useState } from 'react';
import { FiBook, FiVideo, FiHelpCircle, FiMail } from 'react-icons/fi';
import './Help.css';

interface FAQ {
  question: string;
  answer: string;
}

const Help: React.FC = () => {
  const [activeFaq, setActiveFaq] = useState<number | null>(null);
  const [contactForm, setContactForm] = useState({
    name: '',
    email: '',
    subject: '',
    message: ''
  });

  const faqs: FAQ[] = [
    {
      question: 'How does ScoutOut monitor my network?',
      answer: 'ScoutOut uses Raspberry Pi sensors connected to your network to capture and analyze packet data in real-time. The data is processed locally and displayed on this dashboard.'
    },
    {
      question: 'What is a threat score?',
      answer: 'A threat score is a numerical value (0-100) that indicates how dangerous a particular domain or IP address is, based on VirusTotal database and other security intelligence sources.'
    },
    {
      question: 'How do I set up parental controls?',
      answer: 'Navigate to the Parental Controls page, where you can block specific websites, enable category filtering, set time-based restrictions, and assign rules to individual devices.'
    },
    {
      question: 'Can I trust all devices automatically?',
      answer: 'No, we recommend reviewing each new device that joins your network and manually setting its trust level. This helps prevent unauthorized access to your network.'
    },
    {
      question: 'How long is my data stored?',
      answer: 'By default, logs are stored for 30 days. You can adjust this in the Settings page under Data Retention Policies.'
    }
  ];

  const glossary = [
    { term: 'IP Address', definition: 'A unique identifier assigned to each device on a network, like a home address for computers.' },
    { term: 'DNS', definition: 'Domain Name System - translates website names (like google.com) into IP addresses that computers can understand.' },
    { term: 'Packet', definition: 'A small unit of data transmitted over a network. Think of it like a digital envelope containing information.' },
    { term: 'Threat', definition: 'Any potentially malicious activity or connection that could harm your network or devices.' },
    { term: 'MAC Address', definition: 'A unique hardware identifier for network devices, like a serial number for your device\'s network card.' },
    { term: 'Bandwidth', definition: 'The amount of data that can be transmitted over your network connection in a given time period.' }
  ];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    alert('Support request submitted successfully!');
    setContactForm({ name: '', email: '', subject: '', message: '' });
  };

  return (
    <div className="help-page">
      <div className="page-header">
        <h1>Help & Tutorial</h1>
        <p className="subtitle">Learn how to use ScoutOut</p>
      </div>

      {/* Getting Started Guide */}
      <div className="help-section">
        <div className="section-header">
          <FiBook size={24} />
          <h2>Getting Started Guide</h2>
        </div>
        <div className="content-card">
          <h3>How the Pi Sensors Work</h3>
          <p>ScoutOut uses Raspberry Pi devices as network sensors. These sensors passively monitor network traffic by:</p>
          <ol>
            <li>Connecting to your network via ethernet or WiFi</li>
            <li>Capturing packet data using specialized software</li>
            <li>Analyzing the data for threats and patterns</li>
            <li>Sending the processed information to this dashboard</li>
          </ol>

          <h3>How the Dashboard Updates</h3>
          <p>The dashboard automatically refreshes to show real-time information:</p>
          <ul>
            <li>Network traffic updates every 5 seconds</li>
            <li>Threat detection happens in real-time</li>
            <li>Device discovery occurs when new devices join the network</li>
            <li>Statistics are calculated continuously</li>
          </ul>
        </div>
      </div>

      {/* Video Tutorials */}
      <div className="help-section">
        <div className="section-header">
          <FiVideo size={24} />
          <h2>Video Tutorials</h2>
        </div>
        <div className="videos-grid">
          <div className="video-card">
            <div className="video-placeholder">
              <FiVideo size={48} color="#666" />
            </div>
            <h4>Setting Up Parental Controls</h4>
            <p>Learn how to protect your family online with website blocking and time restrictions.</p>
            <button className="watch-btn">Watch Tutorial</button>
          </div>
          <div className="video-card">
            <div className="video-placeholder">
              <FiVideo size={48} color="#666" />
            </div>
            <h4>Understanding Threats</h4>
            <p>Discover how to identify and respond to security threats on your network.</p>
            <button className="watch-btn">Watch Tutorial</button>
          </div>
          <div className="video-card">
            <div className="video-placeholder">
              <FiVideo size={48} color="#666" />
            </div>
            <h4>Identifying Unknown Devices</h4>
            <p>Find out how to recognize and manage devices connected to your network.</p>
            <button className="watch-btn">Watch Tutorial</button>
          </div>
        </div>
      </div>

      {/* FAQ Section */}
      <div className="help-section">
        <div className="section-header">
          <FiHelpCircle size={24} />
          <h2>Frequently Asked Questions</h2>
        </div>
        <div className="faq-list">
          {faqs.map((faq, index) => (
            <div key={index} className={`faq-item ${activeFaq === index ? 'active' : ''}`}>
              <div 
                className="faq-question"
                onClick={() => setActiveFaq(activeFaq === index ? null : index)}
              >
                <span>{faq.question}</span>
                <span className="faq-toggle">{activeFaq === index ? '−' : '+'}</span>
              </div>
              {activeFaq === index && (
                <div className="faq-answer">
                  {faq.answer}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Glossary of Terms */}
      <div className="help-section">
        <div className="section-header">
          <FiBook size={24} />
          <h2>Glossary of Terms</h2>
        </div>
        <div className="glossary-grid">
          {glossary.map((item, index) => (
            <div key={index} className="glossary-item">
              <h4>{item.term}</h4>
              <p>{item.definition}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Support Contact Form */}
      <div className="help-section">
        <div className="section-header">
          <FiMail size={24} />
          <h2>Support Contact Form</h2>
        </div>
        <div className="content-card">
          <p>Need additional help? Contact our support team:</p>
          <form className="contact-form" onSubmit={handleSubmit}>
            <div className="form-row">
              <div className="form-group">
                <label>Name</label>
                <input 
                  type="text" 
                  value={contactForm.name}
                  onChange={(e) => setContactForm({...contactForm, name: e.target.value})}
                  required
                />
              </div>
              <div className="form-group">
                <label>Email</label>
                <input 
                  type="email" 
                  value={contactForm.email}
                  onChange={(e) => setContactForm({...contactForm, email: e.target.value})}
                  required
                />
              </div>
            </div>
            <div className="form-group">
              <label>Subject</label>
              <input 
                type="text" 
                value={contactForm.subject}
                onChange={(e) => setContactForm({...contactForm, subject: e.target.value})}
                required
              />
            </div>
            <div className="form-group">
              <label>Message</label>
              <textarea 
                rows={5}
                value={contactForm.message}
                onChange={(e) => setContactForm({...contactForm, message: e.target.value})}
                required
              />
            </div>
            <button type="submit" className="submit-btn">Send Message</button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Help;
