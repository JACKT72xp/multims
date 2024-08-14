import { createRouter, createWebHistory } from 'vue-router';
import HomeView from '../views/HomeView.vue';
import ConsoleView from '../views/ConsoleView.vue';
import PortForwardSetupView from '../views/PortForwardSetupView.vue';
import SettingsView from '../views/SettingsView.vue';
import AboutView from '../views/AboutView.vue';
const routes = [
    { path: '/', name: 'Home', component: HomeView },
    { path: '/console', name: 'Console', component: ConsoleView },
    { path: '/port-forward', name: 'Port Forward', component: PortForwardSetupView },
    { path: '/settings', name: 'Settings', component: SettingsView },
    { path: '/about', name: 'About', component: AboutView },
];
const router = createRouter({
    history: createWebHistory(import.meta.env.BASE_URL),
    routes,
});
export default router;
