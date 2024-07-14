<template>
  <div class="console-container">
    <Header />
    <Sidebar />
    <main class="main-content">
      <ConsoleTabs />
    </main>
  </div>
</template>

<script setup>
import Header from '../components/Header.vue'
import Sidebar from '../components/Sidebar.vue'
import ConsoleTabs from '../components/ConsoleTabs.vue'
</script>

<style scoped>
.console-container {
  display: flex;
  flex-direction: column;
  height: 100vh;
}

.main-content {
  display: flex;
  flex: 1;
  overflow: hidden;
}
</style>
