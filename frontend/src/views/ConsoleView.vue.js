import Header from '../components/Header.vue';
import Sidebar from '../components/Sidebar.vue';
import ConsoleTabs from '../components/ConsoleTabs.vue';
const { defineProps, defineSlots, defineEmits, defineExpose, defineModel, defineOptions, withDefaults, } = await import('vue');
const __VLS_fnComponent = (await import('vue')).defineComponent({});
let __VLS_functionalComponentProps;
function __VLS_template() {
    let __VLS_ctx;
    /* Components */
    let __VLS_otherComponents;
    let __VLS_own;
    let __VLS_localComponents;
    let __VLS_components;
    let __VLS_styleScopedClasses;
    // CSS variable injection 
    // CSS variable injection end 
    let __VLS_resolvedLocalAndGlobalComponents;
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("console-container") }, });
    // @ts-ignore
    [Header,];
    // @ts-ignore
    const __VLS_0 = __VLS_asFunctionalComponent(Header, new Header({}));
    const __VLS_1 = __VLS_0({}, ...__VLS_functionalComponentArgsRest(__VLS_0));
    ({}({}));
    const __VLS_4 = __VLS_pickFunctionalComponentCtx(Header, __VLS_1);
    // @ts-ignore
    [Sidebar,];
    // @ts-ignore
    const __VLS_5 = __VLS_asFunctionalComponent(Sidebar, new Sidebar({}));
    const __VLS_6 = __VLS_5({}, ...__VLS_functionalComponentArgsRest(__VLS_5));
    ({}({}));
    const __VLS_9 = __VLS_pickFunctionalComponentCtx(Sidebar, __VLS_6);
    __VLS_elementAsFunction(__VLS_intrinsicElements.main, __VLS_intrinsicElements.main)({ ...{ class: ("main-content") }, });
    // @ts-ignore
    [ConsoleTabs,];
    // @ts-ignore
    const __VLS_10 = __VLS_asFunctionalComponent(ConsoleTabs, new ConsoleTabs({}));
    const __VLS_11 = __VLS_10({}, ...__VLS_functionalComponentArgsRest(__VLS_10));
    ({}({}));
    const __VLS_14 = __VLS_pickFunctionalComponentCtx(ConsoleTabs, __VLS_11);
    if (typeof __VLS_styleScopedClasses === 'object' && !Array.isArray(__VLS_styleScopedClasses)) {
        __VLS_styleScopedClasses['console-container'];
        __VLS_styleScopedClasses['main-content'];
    }
    var __VLS_slots;
    return __VLS_slots;
    const __VLS_componentsOption = {};
    let __VLS_name;
    let __VLS_defineComponent;
    const __VLS_internalComponent = __VLS_defineComponent({
        setup() {
            return {
                Header: Header,
                Sidebar: Sidebar,
                ConsoleTabs: ConsoleTabs,
            };
        },
    });
}
export default (await import('vue')).defineComponent({
    setup() {
        return {};
    },
});
;
