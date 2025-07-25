import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const API_BASE_URL = process.env.REACT_APP_BACKEND_URL;

function App() {
  const [latestSummary, setLatestSummary] = useState(null);
  const [recentCVEs, setRecentCVEs] = useState([]);
  const [scrapingStatus, setScrapingStatus] = useState(null);
  const [summaries, setSummaries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  
  // New states for timeline and email management
  const [cveTimeline, setCveTimeline] = useState([]);
  const [timelineStats, setTimelineStats] = useState(null);
  const [emailSubscribers, setEmailSubscribers] = useState([]);
  const [newEmail, setNewEmail] = useState('');
  const [emailConfigStatus, setEmailConfigStatus] = useState(null);
  const [lastVisit, setLastVisit] = useState(null);
  
  // Generate simple session ID
  const [sessionId] = useState(() => {
    let stored = localStorage.getItem('cve_session_id');
    if (!stored) {
      stored = 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
      localStorage.setItem('cve_session_id', stored);
    }
    return stored;
  });

  useEffect(() => {
    fetchData();
    trackVisit();
  }, []);

  const trackVisit = async () => {
    try {
      await axios.post(`${API_BASE_URL}/api/user/visit`, null, {
        params: { session_id: sessionId }
      });
      
      // Get last visit info
      const visitRes = await axios.get(`${API_BASE_URL}/api/user/visit/${sessionId}`);
      setLastVisit(visitRes.data.last_visit);
    } catch (error) {
      console.error('Error tracking visit:', error);
    }
  };

  const fetchData = async () => {
    try {
      setLoading(true);
      const [summaryRes, cvesRes, statusRes, summariesRes, timelineRes, emailConfigRes] = await Promise.all([
        axios.get(`${API_BASE_URL}/api/summaries/latest`),
        axios.get(`${API_BASE_URL}/api/cves/recent`),
        axios.get(`${API_BASE_URL}/api/status`),
        axios.get(`${API_BASE_URL}/api/summaries`),
        axios.get(`${API_BASE_URL}/api/cves/timeline?days=14`),
        axios.get(`${API_BASE_URL}/api/emails/config/status`)
      ]);

      setLatestSummary(summaryRes.data);
      setRecentCVEs(cvesRes.data);
      setScrapingStatus(statusRes.data);
      setSummaries(summariesRes.data);
      setCveTimeline(timelineRes.data);
      setEmailConfigStatus(emailConfigRes.data);
      
      // Fetch email subscribers and timeline stats
      if (emailConfigRes.data.configured) {
        fetchEmailSubscribers();
      }
      fetchTimelineStats();
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchTimelineStats = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/cves/timeline/stats`);
      setTimelineStats(response.data);
    } catch (error) {
      console.error('Error fetching timeline stats:', error);
    }
  };

  const fetchEmailSubscribers = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/emails/subscribers`);
      setEmailSubscribers(response.data);
    } catch (error) {
      console.error('Error fetching email subscribers:', error);
    }
  };

  const addEmailSubscriber = async () => {
    if (!newEmail.trim()) {
      alert('Wprowadź adres email');
      return;
    }
    
    try {
      await axios.post(`${API_BASE_URL}/api/emails/subscribe`, { email: newEmail });
      alert('Email dodany pomyślnie!');
      setNewEmail('');
      fetchEmailSubscribers();
    } catch (error) {
      alert(error.response?.data?.detail || 'Błąd podczas dodawania email');
    }
  };

  const removeEmailSubscriber = async (email) => {
    if (!window.confirm(`Czy na pewno chcesz usunąć email ${email}?`)) return;
    
    try {
      await axios.delete(`${API_BASE_URL}/api/emails/unsubscribe`, { data: { email } });
      alert('Email usunięty pomyślnie!');
      fetchEmailSubscribers();
    } catch (error) {
      alert(error.response?.data?.detail || 'Błąd podczas usuwania email');
    }
  };

  const sendTestEmail = async (email) => {
    try {
      setLoading(true);
      await axios.post(`${API_BASE_URL}/api/emails/send-test`, { email });
      alert(`Test email wysłany na ${email}!`);
    } catch (error) {
      alert(error.response?.data?.detail || 'Błąd wysyłania test email');
    } finally {
      setLoading(false);
    }
  };

  const manualScrape = async () => {
    try {
      setLoading(true);
      await axios.post(`${API_BASE_URL}/api/scrape/manual`);
      await fetchData();
      alert('Scraping ukończony pomyślnie!');
    } catch (error) {
      console.error('Error during manual scrape:', error);
      alert('Błąd podczas scrapingu!');
    } finally {
      setLoading(false);
    }
  };

  const fetchCVEsBySeverity = async (severity) => {
    try {
      setLoading(true);
      let url = `${API_BASE_URL}/api/cves/recent`;
      if (severity !== 'ALL') {
        url = `${API_BASE_URL}/api/cves/by-severity/${severity}`;
      }
      const response = await axios.get(url);
      setRecentCVEs(response.data);
    } catch (error) {
      console.error('Error fetching CVEs by severity:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSeverityChange = (severity) => {
    setSelectedSeverity(severity);
    fetchCVEsBySeverity(severity);
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'CRITICAL': return 'bg-red-100 text-red-800 border-red-200';
      case 'HIGH': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'MEDIUM': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'LOW': return 'bg-green-100 text-green-800 border-green-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString('pl-PL');
  };

  if (loading && !latestSummary) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Ładowanie danych CVE...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <h1 className="text-3xl font-bold text-gray-900">🛡️ CVE Agent</h1>
              </div>
              <p className="ml-4 text-gray-600">Monitorowanie najnowszych zagrożeń bezpieczeństwa</p>
            </div>
            <button
              onClick={manualScrape}
              disabled={loading}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white px-4 py-2 rounded-lg font-medium transition-colors duration-200"
            >
              {loading ? 'Scrapuję...' : 'Scraping Manual'}
            </button>
          </div>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'dashboard'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Dashboard
            </button>
            <button
              onClick={() => setActiveTab('timeline')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'timeline'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              🔥 Timeline CVSS ≥7.0
            </button>
            <button
              onClick={() => setActiveTab('cves')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'cves'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Najnowsze CVE
            </button>
            <button
              onClick={() => setActiveTab('emails')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'emails'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              📧 Email Raporty
            </button>
            <button
              onClick={() => setActiveTab('history')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'history'
                  ? 'border-blue-500 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Historia
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {activeTab === 'dashboard' && (
          <div className="px-4 py-6 sm:px-0">
            {/* Status Card */}
            <div className="bg-white overflow-hidden shadow rounded-lg mb-6">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">Status Scrapingu</h3>
                {scrapingStatus && (
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div className="text-center">
                      <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${
                        scrapingStatus.status === 'completed' ? 'bg-green-100 text-green-800' : 
                        scrapingStatus.status === 'error' ? 'bg-red-100 text-red-800' : 'bg-yellow-100 text-yellow-800'
                      }`}>
                        {scrapingStatus.status === 'completed' ? '✅ Ukończono' : 
                         scrapingStatus.status === 'error' ? '❌ Błąd' : '⏳ W trakcie'}
                      </div>
                    </div>
                    <div className="text-center">
                      <p className="text-sm text-gray-500">Ostatni run</p>
                      <p className="text-lg font-semibold text-gray-900">
                        {scrapingStatus.last_run ? formatDate(scrapingStatus.last_run) : 'Brak danych'}
                      </p>
                    </div>
                    <div className="text-center">
                      <p className="text-sm text-gray-500">Następny run</p>
                      <p className="text-lg font-semibold text-gray-900">Dziś 19:00</p>
                    </div>
                    <div className="text-center">
                      <p className="text-sm text-gray-500">Zebrane elementy</p>
                      <p className="text-lg font-semibold text-gray-900">{scrapingStatus.items_scraped || 0}</p>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Latest Summary */}
            {latestSummary && latestSummary.total_cves && (
              <div className="bg-white overflow-hidden shadow rounded-lg mb-6">
                <div className="px-4 py-5 sm:p-6">
                  <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
                    Dzisiejsze Podsumowanie ({formatDate(latestSummary.date)})
                  </h3>
                  
                  {/* Stats Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                    <div className="bg-gray-50 p-4 rounded-lg text-center">
                      <p className="text-2xl font-bold text-gray-900">{latestSummary.total_cves}</p>
                      <p className="text-sm text-gray-600">Łącznie</p>
                    </div>
                    <div className="bg-red-50 p-4 rounded-lg text-center">
                      <p className="text-2xl font-bold text-red-600">{latestSummary.critical_count}</p>
                      <p className="text-sm text-red-600">Krytyczne</p>
                    </div>
                    <div className="bg-orange-50 p-4 rounded-lg text-center">
                      <p className="text-2xl font-bold text-orange-600">{latestSummary.high_count}</p>
                      <p className="text-sm text-orange-600">Wysokie</p>
                    </div>
                    <div className="bg-yellow-50 p-4 rounded-lg text-center">
                      <p className="text-2xl font-bold text-yellow-600">{latestSummary.medium_count}</p>
                      <p className="text-sm text-yellow-600">Średnie</p>
                    </div>
                    <div className="bg-green-50 p-4 rounded-lg text-center">
                      <p className="text-2xl font-bold text-green-600">{latestSummary.low_count}</p>
                      <p className="text-sm text-green-600">Niskie</p>
                    </div>
                  </div>

                  {/* Summary Text */}
                  <div className="bg-gray-50 p-4 rounded-lg">
                    <pre className="text-sm text-gray-700 whitespace-pre-wrap">{latestSummary.summary_text}</pre>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'timeline' && (
          <div className="px-4 py-6 sm:px-0">
            {/* Timeline Stats */}
            {timelineStats && (
              <div className="bg-white overflow-hidden shadow rounded-lg mb-6">
                <div className="px-4 py-5 sm:p-6">
                  <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
                    📊 Statystyki Timeline CVSS ≥ 7.0
                  </h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="bg-red-50 p-4 rounded-lg text-center">
                      <p className="text-2xl font-bold text-red-600">{timelineStats.total_critical_cves}</p>
                      <p className="text-sm text-red-600">Krytyczne CVE</p>
                    </div>
                    <div className="bg-orange-50 p-4 rounded-lg text-center">
                      <p className="text-2xl font-bold text-orange-600">{timelineStats.total_high_cves}</p>
                      <p className="text-sm text-orange-600">Wysokie CVE</p>
                    </div>
                    <div className="bg-blue-50 p-4 rounded-lg text-center">
                      <p className="text-2xl font-bold text-blue-600">{timelineStats.total_high_severity_cves}</p>
                      <p className="text-sm text-blue-600">Łącznie ≥7.0</p>
                    </div>
                    <div className="bg-gray-50 p-4 rounded-lg text-center">
                      <p className="text-2xl font-bold text-gray-600">{timelineStats.recent_entries_7_days}</p>
                      <p className="text-sm text-gray-600">Dni (7 dni)</p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Timeline Entries */}
            <div className="space-y-6">
              <h3 className="text-xl font-medium text-gray-900">🔥 Dzienny Timeline Wysokich Zagrożeń (CVSS ≥ 7.0)</h3>
              
              {cveTimeline.length === 0 ? (
                <div className="bg-white shadow rounded-lg p-8 text-center">
                  <div className="text-gray-400 text-4xl mb-4">📅</div>
                  <h4 className="text-lg font-medium text-gray-900 mb-2">Brak danych timeline</h4>
                  <p className="text-gray-600">Nie znaleziono CVE o wysokiej wadze w ostatnim czasie.</p>
                  <button
                    onClick={() => axios.post(`${API_BASE_URL}/api/cves/timeline/generate`)}
                    className="mt-4 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
                  >
                    Wygeneruj Timeline dla Dzisiaj
                  </button>
                </div>
              ) : (
                cveTimeline.map((timeline) => (
                  <div key={timeline.id} className="bg-white shadow rounded-lg overflow-hidden">
                    <div className="bg-gradient-to-r from-red-600 to-orange-600 px-6 py-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <h4 className="text-lg font-medium text-white">
                            {new Date(timeline.date).toLocaleDateString('pl-PL', {
                              weekday: 'long',
                              year: 'numeric',
                              month: 'long',
                              day: 'numeric'
                            })}
                          </h4>
                          <p className="text-red-100">
                            {timeline.total_new_count} nowych zagrożeń wysokiej wagi
                          </p>
                        </div>
                        <div className="text-right">
                          <div className="bg-white bg-opacity-20 rounded-lg px-3 py-1 mb-1">
                            <span className="text-white text-sm font-medium">
                              {timeline.new_critical_count} krytycznych
                            </span>
                          </div>
                          <div className="bg-white bg-opacity-20 rounded-lg px-3 py-1">
                            <span className="text-white text-sm font-medium">
                              {timeline.new_high_count} wysokich
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                    
                    <div className="p-6">
                      <div className="space-y-4">
                        {timeline.high_severity_cves.slice(0, 5).map((cve) => (
                          <div key={cve.id} className="border-l-4 border-red-400 pl-4 py-2">
                            <div className="flex items-center justify-between mb-1">
                              <h5 className="font-medium text-gray-900">{cve.title}</h5>
                              <div className="flex items-center space-x-2">
                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(cve.severity)}`}>
                                  {cve.severity}
                                </span>
                                {cve.score && (
                                  <span className="text-sm text-gray-500">
                                    CVSS: {cve.score.toFixed(1)}
                                  </span>
                                )}
                              </div>
                            </div>
                            <p className="text-sm text-gray-600 mb-2">
                              {cve.description.length > 150 
                                ? `${cve.description.substring(0, 150)}...` 
                                : cve.description
                              }
                            </p>
                            <div className="flex items-center justify-between text-xs text-gray-500">
                              <span>Źródło: {cve.source}</span>
                              <a
                                href={cve.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-blue-600 hover:text-blue-800"
                              >
                                Zobacz szczegóły →
                              </a>
                            </div>
                          </div>
                        ))}
                        
                        {timeline.high_severity_cves.length > 5 && (
                          <div className="text-center py-2">
                            <p className="text-sm text-gray-500">
                              ... i {timeline.high_severity_cves.length - 5} więcej zagrożeń tego dnia
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {activeTab === 'emails' && (
          <div className="px-4 py-6 sm:px-0">
            {!emailConfigStatus?.configured ? (
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
                <div className="flex">
                  <div className="flex-shrink-0">
                    <div className="w-5 h-5 text-yellow-400">⚠️</div>
                  </div>
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-yellow-800">
                      Gmail nie jest skonfigurowany
                    </h3>
                    <p className="mt-2 text-sm text-yellow-700">
                      Aby włączyć raporty email, administrator musi skonfigurować GMAIL_USER i GMAIL_APP_PASSWORD w pliku .env
                    </p>
                  </div>
                </div>
              </div>
            ) : (
              <>
                {/* Email Configuration Status */}
                <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-6">
                  <div className="flex">
                    <div className="flex-shrink-0">
                      <div className="w-5 h-5 text-green-400">✅</div>
                    </div>
                    <div className="ml-3">
                      <h3 className="text-sm font-medium text-green-800">
                        Gmail skonfigurowany pomyślnie
                      </h3>
                      <p className="mt-2 text-sm text-green-700">
                        Email: {emailConfigStatus.gmail_user} | Template: {emailConfigStatus.template_available ? '✅' : '❌'}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Add New Email */}
                <div className="bg-white shadow rounded-lg mb-6">
                  <div className="px-4 py-5 sm:p-6">
                    <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
                      📧 Zarządzaj Subskrypcjami Email
                    </h3>
                    <div className="flex space-x-3">
                      <input
                        type="email"
                        placeholder="nazwa@przykład.com"
                        value={newEmail}
                        onChange={(e) => setNewEmail(e.target.value)}
                        className="flex-1 min-w-0 rounded-md border-gray-300 px-3 py-2 focus:border-blue-500 focus:ring-blue-500"
                      />
                      <button
                        onClick={addEmailSubscriber}
                        className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
                      >
                        Dodaj Email
                      </button>
                    </div>
                  </div>
                </div>

                {/* Email Subscribers List */}
                <div className="bg-white shadow rounded-lg">
                  <div className="px-4 py-5 sm:p-6">
                    <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">
                      Lista Subskrybentów ({emailSubscribers.length})
                    </h3>
                    
                    {emailSubscribers.length === 0 ? (
                      <p className="text-gray-500 text-center py-8">Brak subskrybentów email</p>
                    ) : (
                      <div className="space-y-3">
                        {emailSubscribers.map((subscriber) => (
                          <div key={subscriber.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                            <div>
                              <p className="font-medium text-gray-900">{subscriber.email}</p>
                              <p className="text-sm text-gray-500">
                                Dodany: {formatDate(subscriber.added_at)}
                              </p>
                            </div>
                            <div className="flex space-x-2">
                              <button
                                onClick={() => sendTestEmail(subscriber.email)}
                                className="text-blue-600 hover:text-blue-800 text-sm font-medium"
                                disabled={loading}
                              >
                                Test Email
                              </button>
                              <button
                                onClick={() => removeEmailSubscriber(subscriber.email)}
                                className="text-red-600 hover:text-red-800 text-sm font-medium"
                              >
                                Usuń
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {activeTab === 'cves' && (
          <div className="px-4 py-6 sm:px-0">
            {/* Severity Filter */}
            <div className="mb-6">
              <div className="flex flex-wrap gap-2">
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(severity => (
                  <button
                    key={severity}
                    onClick={() => handleSeverityChange(severity)}
                    className={`px-4 py-2 rounded-lg font-medium transition-colors duration-200 ${
                      selectedSeverity === severity
                        ? 'bg-blue-600 text-white'
                        : 'bg-white text-gray-700 hover:bg-gray-50 border border-gray-300'
                    }`}
                  >
                    {severity === 'ALL' ? 'Wszystkie' : severity}
                  </button>
                ))}
              </div>
            </div>

            {/* CVE List */}
            <div className="bg-white shadow overflow-hidden sm:rounded-md">
              <ul className="divide-y divide-gray-200">
                {recentCVEs.map((cve) => (
                  <li key={cve.id}>
                    <div className="px-4 py-4 sm:px-6 hover:bg-gray-50">
                      <div className="flex items-center justify-between">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <p className="text-lg font-medium text-gray-900 truncate">
                              {cve.title}
                            </p>
                            <div className="flex items-center space-x-2">
                              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${getSeverityColor(cve.severity)}`}>
                                {cve.severity}
                              </span>
                              {cve.score && (
                                <span className="text-sm text-gray-500">
                                  Score: {cve.score}
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="mt-2">
                            <p className="text-sm text-gray-600 line-clamp-2">
                              {cve.description}
                            </p>
                          </div>
                          <div className="mt-2 flex items-center justify-between">
                            <div className="flex items-center space-x-4">
                              <span className="text-sm text-gray-500">
                                Źródło: {cve.source}
                              </span>
                              {cve.cve_id && (
                                <span className="text-sm text-gray-500">
                                  ID: {cve.cve_id}
                                </span>
                              )}
                            </div>
                            <div className="flex items-center space-x-2">
                              <span className="text-sm text-gray-500">
                                {formatDate(cve.scraped_at)}
                              </span>
                              <a
                                href={cve.url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-blue-600 hover:text-blue-800 text-sm font-medium"
                              >
                                Zobacz więcej →
                              </a>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
              {recentCVEs.length === 0 && (
                <div className="text-center py-12">
                  <p className="text-gray-500">Brak danych CVE. Kliknij "Scraping Manual" aby pobrać najnowsze dane.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'history' && (
          <div className="px-4 py-6 sm:px-0">
            <div className="bg-white shadow overflow-hidden sm:rounded-md">
              <div className="px-4 py-5 sm:p-6">
                <h3 className="text-lg leading-6 font-medium text-gray-900 mb-4">Historia Podsumowań</h3>
                <div className="space-y-4">
                  {summaries.map((summary) => (
                    <div key={summary.id} className="border border-gray-200 rounded-lg p-4">
                      <div className="flex justify-between items-start mb-2">
                        <h4 className="text-md font-medium text-gray-900">
                          {formatDate(summary.date)}
                        </h4>
                        <div className="flex space-x-4 text-sm text-gray-600">
                          <span>Łącznie: {summary.total_cves}</span>
                          <span className="text-red-600">Krytyczne: {summary.critical_count}</span>
                          <span className="text-orange-600">Wysokie: {summary.high_count}</span>
                        </div>
                      </div>
                      <div className="bg-gray-50 p-3 rounded text-sm">
                        <pre className="text-gray-700 whitespace-pre-wrap">{summary.summary_text}</pre>
                      </div>
                    </div>
                  ))}
                  {summaries.length === 0 && (
                    <p className="text-gray-500 text-center py-8">Brak historii podsumowań.</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;