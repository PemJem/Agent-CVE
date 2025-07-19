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
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [summaryRes, cvesRes, statusRes, summariesRes] = await Promise.all([
        axios.get(`${API_BASE_URL}/api/summaries/latest`),
        axios.get(`${API_BASE_URL}/api/cves/recent`),
        axios.get(`${API_BASE_URL}/api/status`),
        axios.get(`${API_BASE_URL}/api/summaries`)
      ]);

      setLatestSummary(summaryRes.data);
      setRecentCVEs(cvesRes.data);
      setScrapingStatus(statusRes.data);
      setSummaries(summariesRes.data);
    } catch (error) {
      console.error('Error fetching data:', error);
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