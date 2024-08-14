<template>
  <div class="config-setup">
    <div v-if="hasSavedConfig" class="config-loader">
      <div class="alert alert-warning mb-4">
        Use the previously saved kubeconfig?
      </div>
      <button @click="loadSavedKubeConfig" class="btn-primary mb-4">Use Saved Kubeconfig</button>
    </div>
    <div>
      <input type="file" @change="loadKubeConfigFromFile" class="btn-primary mb-4" />
      <button @click="loadKubeConfigDefault" class="btn-primary">Use Default Kubeconfig</button>
    </div>
  </div>
</template>

<script setup>
import { ref, defineEmits } from 'vue';
import yaml from 'js-yaml';
import axios from 'axios';

const emit = defineEmits(['configLoaded']);

const error = ref('');
const clusters = ref([]);
const hasSavedConfig = ref(false);

const loadKubeConfigFromFile = async (event) => {
  try {
    const file = event.target.files[0];
    const text = await file.text();
    const config = yaml.load(text);

    if (config && Array.isArray(config.clusters)) {
      clusters.value = config.clusters.map(cluster => ({
        name: cluster.name || 'Unnamed Cluster',
        server: cluster.server || 'Server not specified'
      }));
      saveKubeConfig(config);
      emit('configLoaded', clusters.value);
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

    if (config && Array.isArray(config.clusters)) {
      clusters.value = config.clusters.map(cluster => ({
        name: cluster.name || 'Unnamed Cluster',
        server: cluster.server || 'Server not specified'
      }));
      saveKubeConfig(config);
      emit('configLoaded', clusters.value);
    } else {
      throw new Error('Invalid kubeconfig format');
    }
  } catch (err) {
    error.value = 'Failed to load kubeconfig: ' + err.message;
    console.error('Default kubeconfig loading error:', err);
  }
};

const saveKubeConfig = (config) => {
  const kubeConfigs = JSON.parse(localStorage.getItem('kubeConfigs')) || [];
  kubeConfigs.push(config);
  localStorage.setItem('kubeConfigs', JSON.stringify(kubeConfigs));
};

const loadSavedKubeConfig = () => {
  const kubeConfigs = JSON.parse(localStorage.getItem('kubeConfigs'));
  if (kubeConfigs && kubeConfigs.length > 0) {
    clusters.value = kubeConfigs[0].clusters.map(cluster => ({
      name: cluster.name || 'Unnamed Cluster',
      server: cluster.server || 'Server not specified'
    }));
    emit('configLoaded', clusters.value);
  }
};

const checkForSavedConfig = () => {
  const kubeConfigs = JSON.parse(localStorage.getItem('kubeConfigs'));
  if (kubeConfigs && kubeConfigs.length > 0) {
    hasSavedConfig.value = true;
  }
};

checkForSavedConfig();
</script>

<style scoped>
.config-setup {
  text-align: center;
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
</style>
