<template>
  <div class="console-tabs-container">
    <TabContainer>
      <template #default="{ activeTab, tabs }">
        <Terminal
          v-for="(tab, index) in tabs"
          :key="index"
          v-show="index === activeTab"
          :tabIndex="index"
        />
      </template>
    </TabContainer>
  </div>
</template>

<script setup>
import TabContainer from './TabContainer.vue'
import Terminal from './Terminal.vue'
</script>

<style scoped>
.console-tabs-container {
  display: flex;
  flex-direction: column;
  height: 100%;
  width: 100%;
}

.tab-content {
  flex: 1;
  display: flex;
  flex-direction: column;
}
</style>
