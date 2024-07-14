import { createRouter, createWebHistory } from 'vue-router';
import HomeView from '../views/HomeView.vue';
import ConsoleView from '../views/ConsoleView.vue';
import PortForwardSetup from '../views/PortForwardSetupView.vue'; // Asegúrate de que la importación sea correcta


const routes = [
  {
    path: '/',
    name: 'Home',
    component: HomeView,
  },
  {
    path: '/console',
    name: 'Console',
    component: ConsoleView,
  },
  {
    path: '/port-forward',
    name: 'PortForward',
    component: PortForwardSetup,
  },
];

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
});

export default router;
