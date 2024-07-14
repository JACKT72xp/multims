<template>
  <div class="port-forward-setup">
    <div class="card">
      <h2 class="title">Port Forward Setup</h2>
      <div v-if="error" class="alert alert-error">
        {{ error }}
      </div>
      <div v-if="!configLoaded" class="config-loader">
        <div class="alert alert-warning mb-4">
          No multims.yaml found. Loading default kubeconfig...
        </div>
        <input type="file" @change="loadKubeConfigFromFile" class="btn-primary mb-4" />
        <button @click="loadKubeConfigDefault" class="btn-primary">Use Default Kubeconfig</button>
      </div>
      <div v-else>
        <p class="instruction">Select a cluster to continue:</p>
        <ul class="cluster-list">
          <li v-for="cluster in clusters" :key="cluster.name">
            <button @click="selectCluster(cluster)" class="btn-cluster">
              {{ cluster.name }} - {{ cluster.server }}
            </button>
          </li>
        </ul>
        <div v-if="selectedCluster">
          <h3 class="cluster-title">{{ selectedCluster.name }}</h3>
          <button @click="selectInternal" class="btn-secondary">Forward Internal Service</button>
          <button @click="selectExternal" class="btn-secondary">Forward External Service</button>
          <InternalServiceSetup v-if="showInternal" :cluster="selectedCluster" />
          <ExternalServiceSetup v-if="showExternal" :cluster="selectedCluster" />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import yaml from 'js-yaml';
import axios from 'axios';
import InternalServiceSetup from '../components/InternalServiceSetup.vue';
import ExternalServiceSetup from '../components/ExternalServiceSetup.vue';

const error = ref('');
const clusters = ref([]);
const selectedCluster = ref(null);
const configLoaded = ref(false);
const showInternal = ref(false);
const showExternal = ref(false);

const loadKubeConfigFromFile = async (event) => {
  try {
    const file = event.target.files[0];
    const text = await file.text();
    const config = yaml.load(text);

    console.log('Loaded kubeconfig:', config);

    if (config && Array.isArray(config.clusters)) {
      clusters.value = config.clusters.map(cluster => ({
        name: cluster.name || 'Unnamed Cluster',
        server: cluster.server || 'Server not specified'
      }));
      configLoaded.value = true;
    } else {
      throw new Error('Invalid kubeconfig format');
    }
  } catch (err) {
    error.value = 'Failed to load kubeconfig: ' + err.message;
    console.error('Kubeconfig loading error:', err);
  }
};

const loadKubeConfigDefault = async () => {
  try {
    const response = await axios.get('/api/load-kube-config');
    const config = response.data;

    console.log('Loaded default kubeconfig:', config);

    if (config && Array.isArray(config.clusters)) {
      clusters.value = config.clusters.map(cluster => ({
        name: cluster.name || 'Unnamed Cluster',
        server: cluster.server || 'Server not specified'
      }));
      configLoaded.value = true;
    } else {
      throw new Error('Invalid kubeconfig format');
    }
  } catch (err) {
    error.value = 'Failed to load kubeconfig: ' + err.message;
    console.error('Default kubeconfig loading error:', err);
  }
};

const selectCluster = (cluster) => {
  selectedCluster.value = cluster;
  showInternal.value = false;
  showExternal.value = false;
};

const selectInternal = () => {
  showInternal.value = true;
  showExternal.value = false;
};

const selectExternal = () => {
  showInternal.value = false;
  showExternal.value = true;
};
</script>

<style scoped>
:root {
  --color-primary: #0A84FF;
  --color-secondary: #FF9500;
  --color-dark: #1C1C1E;
  --color-light: #F2F2F7;
  --background-gradient: linear-gradient(135deg, #1f2937, #111827);
}

body {
  background: var(--background-gradient);
  color: var(--color-light);
  font-family: 'Inter', sans-serif;
}

.port-forward-setup {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100vh;
}

.card {
  background: #2d3748;
  padding: 2rem;
  border-radius: 1rem;
  box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
  text-align: center;
  max-width: 600px;
  width: 100%;
}

.title {
  font-size: 2rem;
  font-weight: bold;
  margin-bottom: 1rem;
}

.alert {
  padding: 1rem;
  margin-bottom: 1rem;
  border: 1px solid transparent;
  border-radius: 0.25rem;
}

.alert-warning {
  color: #856404;
  background-color: #fff3cd;
  border-color: #ffeeba;
}

.alert-error {
  color: #f44336;
  background-color: #fddede;
  border-color: #f44336;
}

.btn-primary {
  display: inline-block;
  padding: 0.75rem 1.5rem;
  margin: 0.5rem 0;
  font-size: 1rem;
  font-weight: bold;
  cursor: pointer;
  text-align: center;
  text-decoration: none;
  color: var(--color-light);
  background-color: var(--color-primary);
  border: none;
  border-radius: 0.5rem;
  transition: background-color 0.3s ease-in-out, transform 0.3s;
}

.btn-primary:hover {
  background-color: #0056b3;
  transform: translateY(-2px);
}

.btn-secondary {
  display: inline-block;
  padding: 0.75rem 1.5rem;
  margin: 0.5rem 0.5rem 0 0;
  font-size: 1rem;
  font-weight: bold;
  cursor: pointer;
  text-align: center;
  text-decoration: none;
  color: var(--color-dark);
  background-color: var(--color-secondary);
  border: none;
  border-radius: 0.5rem;
  transition: background-color 0.3s ease-in-out, transform 0.3s;
}

.btn-secondary:hover {
  background-color: #e67e22;
  transform: translateY(-2px);
}

.instruction {
  font-size: 1.25rem;
  margin-bottom: 1rem;
}

.cluster-list {
  list-style-type: none;
  padding: 0;
  margin: 0 0 1.5rem 0;
}

.btn-cluster {
  display: block;
  width: 100%;
  padding: 0.75rem 1.5rem;
  margin: 0.5rem 0;
  font-size: 1rem;
  font-weight: bold;
  cursor: pointer;
  text-align: left;
  text-decoration: none;
  color: var(--color-light);
  background-color: #4a5568;
  border: none;
  border-radius: 0.5rem;
  transition: background-color 0.3s ease-in-out, transform 0.3s;
}

.btn-cluster:hover {
  background-color: #2d3748;
  transform: translateY(-2px);
}

.cluster-title {
  font-size: 1.5rem;
  font-weight: bold;
  margin: 1.5rem 0;
}
</style>
