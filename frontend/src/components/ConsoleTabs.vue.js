import TabContainer from './TabContainer.vue';
import Terminal from './Terminal.vue';
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
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("console-tabs-container") }, });
    // @ts-ignore
    [TabContainer, TabContainer,];
    // @ts-ignore
    const __VLS_0 = __VLS_asFunctionalComponent(TabContainer, new TabContainer({}));
    const __VLS_1 = __VLS_0({}, ...__VLS_functionalComponentArgsRest(__VLS_0));
    ({}({}));
    __VLS_elementAsFunction(__VLS_intrinsicElements.template, __VLS_intrinsicElements.template)({});
    {
        const [{ activeTab, tabs }] = __VLS_getSlotParams((__VLS_4.slots).default);
        for (const [tab, index] of __VLS_getVForSourceType((tabs))) {
            // @ts-ignore
            [Terminal,];
            // @ts-ignore
            const __VLS_5 = __VLS_asFunctionalComponent(Terminal, new Terminal({ key: ((index)), tabIndex: ((index)), }));
            const __VLS_6 = __VLS_5({ key: ((index)), tabIndex: ((index)), }, ...__VLS_functionalComponentArgsRest(__VLS_5));
            ({}({ key: ((index)), tabIndex: ((index)), }));
            __VLS_directiveFunction(__VLS_ctx.vShow)((index === activeTab));
            // @ts-ignore
            [vShow,];
            const __VLS_9 = __VLS_pickFunctionalComponentCtx(Terminal, __VLS_6);
        }
    }
    const __VLS_4 = __VLS_pickFunctionalComponentCtx(TabContainer, __VLS_1);
    if (typeof __VLS_styleScopedClasses === 'object' && !Array.isArray(__VLS_styleScopedClasses)) {
        __VLS_styleScopedClasses['console-tabs-container'];
    }
    var __VLS_slots;
    return __VLS_slots;
    const __VLS_componentsOption = {};
    let __VLS_name;
    let __VLS_defineComponent;
    const __VLS_internalComponent = __VLS_defineComponent({
        setup() {
            return {
                TabContainer: TabContainer,
                Terminal: Terminal,
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
