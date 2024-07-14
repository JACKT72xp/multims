<template>
  <div class="tab-container">
    <div class="tabs">
      <div
        v-for="(tab, index) in tabs"
        :key="index"
        :class="['tab', { 'active-tab': index === activeTab }]"
        @click="setActiveTab(index)"
      >
        {{ tab.name }}
        <button @click.stop="removeTab(index)">×</button>
      </div>
      <button @click="addTab" class="add-tab">+</button>
    </div>
    <div class="tab-content">
      <slot :activeTab="activeTab" :tabs="tabs"></slot>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'

const tabs = ref([{ name: 'Console 1' }, { name: 'Console 2' }])
const activeTab = ref(0)

const setActiveTab = (index) => {
  activeTab.value = index
}

const addTab = () => {
  tabs.value.push({ name: `Console ${tabs.value.length + 1}` })
  activeTab.value = tabs.value.length - 1
}

const removeTab = (index) => {
  tabs.value.splice(index, 1)
  if (activeTab.value >= tabs.value.length) {
    activeTab.value = tabs.value.length - 1
  }
}
</script>

<style scoped>
.tab-container {
  display: flex;
  flex-direction: column;
  height: 100%;
  width: 100%;
}

.tabs {
  display: flex;
  background-color: #1a202c;
  color: white;
  padding: 10px;
}

.tab {
  padding: 10px;
  cursor: pointer;
  display: flex;
  align-items: center;
  background-color: #2d3748;
  margin-right: 5px;
  border-radius: 5px;
}

.active-tab {
  background-color: #4a5568;
}

.tab button {
  margin-left: 10px;
  background: none;
  border: none;
  color: white;
  cursor: pointer;
}

.add-tab {
  padding: 10px;
  background-color: #2d3748;
  color: white;
  border: none;
  cursor: pointer;
  border-radius: 5px;
}

.tab-content {
  flex: 1;
  padding: 10px;
  background-color: #2d3748;
  border-radius: 5px;
  width: 100%
}
</style>
