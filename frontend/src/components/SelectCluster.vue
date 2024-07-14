<template>
  <div>
    <ul>
      <li v-for="cluster in clusters" :key="cluster.name" @click="selectCluster(cluster)" class="cursor-pointer hover:bg-blue-100 p-2 rounded">
        {{ cluster.name }} ({{ cluster.server }})
      </li>
    </ul>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue';

const props = defineProps({
  kubeConfig: Object,
});

const emit = defineEmits(['cluster-selected']);

const clusters = ref([]);

watch(() => props.kubeConfig, (newConfig) => {
  if (newConfig && newConfig.clusters) {
    clusters.value = newConfig.clusters.map(cluster => ({
      name: cluster.name,
      server: cluster.cluster.server,
    }));
  }
});

const selectCluster = (cluster) => {
  emit('cluster-selected', cluster);
};
</script>
